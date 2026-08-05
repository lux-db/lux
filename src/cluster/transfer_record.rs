use super::{ClusterError, CompiledExecution, TransferDataKey, TransferDescriptor};
use crate::snapshot::{dump_value_type, read_dump_value, write_dump_value};
use crate::store::{DumpValue, Store};
use std::collections::HashSet;
use std::io::{Read, Write};

const RECORD_MAGIC: &[u8; 4] = b"LXRD";
const RECORD_SCHEMA_VERSION: u16 = 2;
const RECORD_END: u8 = 0;
const RECORD_DELETE_KV: u8 = 1;
const RECORD_UPSERT_KV: u8 = 2;
const RECORD_DELETE_TABLE_ROW: u8 = 3;
const RECORD_UPSERT_TABLE_ROW: u8 = 4;
const MAX_RECORD_KEY_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD_NAME_BYTES: usize = 256;
const MAX_TABLE_VECTOR_FIELDS: usize = 4_096;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TableVectorRecord {
    pub field: String,
    pub value: DumpValue,
    pub expires_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TransferRecord {
    Delete(TransferDataKey),
    UpsertKv {
        key: Vec<u8>,
        value: DumpValue,
        expires_at_ms: Option<i64>,
    },
    UpsertTableRow {
        table: String,
        primary_key: Vec<u8>,
        order_score: f64,
        value: DumpValue,
        expires_at_ms: Option<i64>,
        vectors: Vec<TableVectorRecord>,
    },
}

impl TransferRecord {
    pub(crate) fn identity(&self) -> Result<TransferDataKey, ClusterError> {
        match self {
            Self::Delete(identity) => Ok(identity.clone()),
            Self::UpsertKv { key, .. } => TransferDataKey::kv(key.clone()),
            Self::UpsertTableRow {
                table, primary_key, ..
            } => TransferDataKey::table_row(table.clone(), primary_key.clone()),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ClusterError> {
        let identity = self.identity()?;
        match self {
            Self::Delete(_) => {}
            Self::UpsertKv { expires_at_ms, .. } => validate_expiry(*expires_at_ms)?,
            Self::UpsertTableRow {
                table,
                primary_key,
                order_score,
                value,
                expires_at_ms,
                vectors,
            } => {
                validate_expiry(*expires_at_ms)?;
                if !order_score.is_finite() {
                    return invalid("table-row order score must be finite");
                }
                validate_table_hash(value)?;
                if std::str::from_utf8(primary_key).is_err() {
                    return invalid("table-row primary key must be UTF-8");
                }
                if vectors.len() > MAX_TABLE_VECTOR_FIELDS {
                    return invalid("table row has too many vector fields");
                }
                let mut fields = HashSet::with_capacity(vectors.len());
                for vector in vectors {
                    validate_field(&vector.field)?;
                    validate_expiry(vector.expires_at_ms)?;
                    if !matches!(vector.value, DumpValue::Vector(..)) {
                        return invalid("table vector sidecar must contain a vector");
                    }
                    if !fields.insert(vector.field.as_str()) {
                        return invalid("table row contains duplicate vector sidecars");
                    }
                    table_vector_key(table, &vector.field, primary_key)?;
                }
            }
        }
        if identity.slot() >= super::CLUSTER_SLOT_COUNT {
            return invalid("transfer record maps outside the cluster slot space");
        }
        Ok(())
    }
}

pub(crate) struct TransferRecordWriter<'a, W> {
    inner: W,
    store: &'a Store,
    descriptor: &'a TransferDescriptor,
    execution: &'a CompiledExecution,
    records: u64,
    finished: bool,
}

impl<'a, W: Write> TransferRecordWriter<'a, W> {
    pub(crate) fn new(
        mut inner: W,
        store: &'a Store,
        descriptor: &'a TransferDescriptor,
        execution: &'a CompiledExecution,
    ) -> Result<Self, ClusterError> {
        descriptor.validate()?;
        validate_execution(descriptor, execution)?;
        inner.write_all(RECORD_MAGIC)?;
        inner.write_all(&RECORD_SCHEMA_VERSION.to_be_bytes())?;
        inner.write_all(&descriptor.transfer_id.0)?;
        inner.write_all(&execution.manifest().version.to_be_bytes())?;
        inner.write_all(execution.digest().as_bytes())?;
        Ok(Self {
            inner,
            store,
            descriptor,
            execution,
            records: 0,
            finished: false,
        })
    }

    pub(crate) fn write_record(&mut self, record: &TransferRecord) -> Result<(), ClusterError> {
        if self.finished {
            return invalid("transfer record stream is already finished");
        }
        record.validate()?;
        validate_record_execution(record, self.execution)?;
        let identity = record.identity()?;
        if !self.descriptor.contains_slot(identity.slot()) {
            return invalid("transfer record is outside the ownership movement");
        }
        match record {
            TransferRecord::Delete(TransferDataKey::Kv(key)) => {
                self.inner.write_all(&[RECORD_DELETE_KV])?;
                write_bytes(&mut self.inner, key)?;
            }
            TransferRecord::Delete(TransferDataKey::TableRow { table, primary_key }) => {
                self.inner.write_all(&[RECORD_DELETE_TABLE_ROW])?;
                write_name(&mut self.inner, table)?;
                write_bytes(&mut self.inner, primary_key)?;
            }
            TransferRecord::UpsertKv {
                key,
                value,
                expires_at_ms,
            } => {
                self.inner.write_all(&[RECORD_UPSERT_KV])?;
                write_bytes(&mut self.inner, key)?;
                write_expiry(&mut self.inner, *expires_at_ms)?;
                self.inner.write_all(&[dump_value_type(value)])?;
                write_dump_value(&mut self.inner, self.store, key, value)?;
            }
            TransferRecord::UpsertTableRow {
                table,
                primary_key,
                order_score,
                value,
                expires_at_ms,
                vectors,
            } => {
                self.inner.write_all(&[RECORD_UPSERT_TABLE_ROW])?;
                write_name(&mut self.inner, table)?;
                write_bytes(&mut self.inner, primary_key)?;
                self.inner.write_all(&order_score.to_bits().to_be_bytes())?;
                write_expiry(&mut self.inner, *expires_at_ms)?;
                let row_key = table_row_key(table, primary_key)?;
                self.inner.write_all(&[dump_value_type(value)])?;
                write_dump_value(&mut self.inner, self.store, &row_key, value)?;
                write_u32(&mut self.inner, vectors.len())?;
                for vector in vectors {
                    write_name(&mut self.inner, &vector.field)?;
                    write_expiry(&mut self.inner, vector.expires_at_ms)?;
                    self.inner.write_all(&[dump_value_type(&vector.value)])?;
                    let vector_key = table_vector_key(table, &vector.field, primary_key)?;
                    write_dump_value(&mut self.inner, self.store, &vector_key, &vector.value)?;
                }
            }
        }
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| ClusterError::InvalidTransfer("record count is exhausted".to_owned()))?;
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<(), ClusterError> {
        self.inner.flush()?;
        Ok(())
    }

    pub(crate) fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub(crate) fn finish(mut self) -> Result<W, ClusterError> {
        if self.finished {
            return invalid("transfer record stream is already finished");
        }
        self.inner.write_all(&[RECORD_END])?;
        self.inner.write_all(&self.records.to_be_bytes())?;
        self.inner.flush()?;
        self.finished = true;
        Ok(self.inner)
    }
}

pub(crate) struct TransferRecordReader<'a, R> {
    inner: R,
    store: &'a Store,
    descriptor: &'a TransferDescriptor,
    execution: &'a CompiledExecution,
    records: u64,
    finished: bool,
}

impl<'a, R: Read> TransferRecordReader<'a, R> {
    pub(crate) fn new(
        mut inner: R,
        store: &'a Store,
        descriptor: &'a TransferDescriptor,
        execution: &'a CompiledExecution,
    ) -> Result<Self, ClusterError> {
        descriptor.validate()?;
        validate_execution(descriptor, execution)?;
        let mut magic = [0_u8; 4];
        inner.read_exact(&mut magic)?;
        if &magic != RECORD_MAGIC {
            return invalid("transfer record stream has an invalid header");
        }
        let schema = read_u16(&mut inner)?;
        if schema != RECORD_SCHEMA_VERSION {
            return invalid("transfer record stream has an unsupported schema");
        }
        let mut transfer_id = [0_u8; 32];
        inner.read_exact(&mut transfer_id)?;
        if transfer_id != descriptor.transfer_id.0 {
            return invalid("transfer record stream belongs to another transfer");
        }
        let execution_version = read_u64(&mut inner)?;
        if execution_version != execution.manifest().version {
            return invalid("transfer record stream uses another execution version");
        }
        let mut execution_digest = [0_u8; 64];
        inner.read_exact(&mut execution_digest)?;
        if execution_digest != execution.digest().as_bytes() {
            return invalid("transfer record stream uses another execution digest");
        }
        Ok(Self {
            inner,
            store,
            descriptor,
            execution,
            records: 0,
            finished: false,
        })
    }

    pub(crate) fn next_record(&mut self) -> Result<Option<TransferRecord>, ClusterError> {
        if self.finished {
            return Ok(None);
        }
        let mut tag = [0_u8; 1];
        self.inner.read_exact(&mut tag).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                ClusterError::InvalidTransfer(
                    "transfer record stream ended before its final marker".to_owned(),
                )
            } else {
                error.into()
            }
        })?;
        if tag[0] == RECORD_END {
            let expected = read_u64(&mut self.inner)?;
            if expected != self.records {
                return invalid("transfer record count does not match its final marker");
            }
            let mut trailing = [0_u8; 1];
            if self.inner.read(&mut trailing)? != 0 {
                return invalid("transfer record stream contains trailing bytes");
            }
            self.finished = true;
            return Ok(None);
        }
        let record = match tag[0] {
            RECORD_DELETE_KV => TransferRecord::Delete(TransferDataKey::kv(read_bytes(
                &mut self.inner,
                MAX_RECORD_KEY_BYTES,
            )?)?),
            RECORD_UPSERT_KV => {
                let key = read_bytes(&mut self.inner, MAX_RECORD_KEY_BYTES)?;
                let expires_at_ms = read_expiry(&mut self.inner)?;
                let value_type = read_u8(&mut self.inner)?;
                let value = read_dump_value(self.store, &mut self.inner, value_type, &key, true)?;
                TransferRecord::UpsertKv {
                    key,
                    value,
                    expires_at_ms,
                }
            }
            RECORD_DELETE_TABLE_ROW => {
                let table = read_name(&mut self.inner)?;
                let primary_key = read_bytes(&mut self.inner, MAX_RECORD_KEY_BYTES)?;
                TransferRecord::Delete(TransferDataKey::table_row(table, primary_key)?)
            }
            RECORD_UPSERT_TABLE_ROW => {
                let table = read_name(&mut self.inner)?;
                let primary_key = read_bytes(&mut self.inner, MAX_RECORD_KEY_BYTES)?;
                let order_score = f64::from_bits(read_u64(&mut self.inner)?);
                let expires_at_ms = read_expiry(&mut self.inner)?;
                let row_key = table_row_key(&table, &primary_key)?;
                let value_type = read_u8(&mut self.inner)?;
                let value =
                    read_dump_value(self.store, &mut self.inner, value_type, &row_key, true)?;
                let vector_count = read_u32(&mut self.inner)? as usize;
                if vector_count > MAX_TABLE_VECTOR_FIELDS {
                    return invalid("table row has too many vector fields");
                }
                let mut vectors = Vec::with_capacity(vector_count);
                for _ in 0..vector_count {
                    let field = read_name(&mut self.inner)?;
                    let vector_expiry = read_expiry(&mut self.inner)?;
                    let vector_type = read_u8(&mut self.inner)?;
                    let vector_key = table_vector_key(&table, &field, &primary_key)?;
                    let vector = read_dump_value(
                        self.store,
                        &mut self.inner,
                        vector_type,
                        &vector_key,
                        true,
                    )?;
                    vectors.push(TableVectorRecord {
                        field,
                        value: vector,
                        expires_at_ms: vector_expiry,
                    });
                }
                TransferRecord::UpsertTableRow {
                    table,
                    primary_key,
                    order_score,
                    value,
                    expires_at_ms,
                    vectors,
                }
            }
            _ => return invalid("transfer record stream contains an unknown record kind"),
        };
        record.validate()?;
        validate_record_execution(&record, self.execution)?;
        if !self.descriptor.contains_slot(record.identity()?.slot()) {
            return invalid("transfer record is outside the ownership movement");
        }
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| ClusterError::InvalidTransfer("record count is exhausted".to_owned()))?;
        Ok(Some(record))
    }
}

fn validate_execution(
    descriptor: &TransferDescriptor,
    execution: &CompiledExecution,
) -> Result<(), ClusterError> {
    if execution.manifest().cluster_id != descriptor.cluster_id {
        return invalid("transfer execution metadata belongs to another cluster");
    }
    if execution.digest().len() != 64 || !execution.digest().is_ascii() {
        return invalid("transfer execution digest is not canonical");
    }
    Ok(())
}

fn validate_record_execution(
    record: &TransferRecord,
    execution: &CompiledExecution,
) -> Result<(), ClusterError> {
    let (table, vectors) = match record {
        TransferRecord::Delete(TransferDataKey::TableRow { table, .. }) => (table.as_str(), None),
        TransferRecord::UpsertTableRow { table, vectors, .. } => {
            (table.as_str(), Some(vectors.as_slice()))
        }
        TransferRecord::Delete(TransferDataKey::Kv(_)) | TransferRecord::UpsertKv { .. } => {
            return Ok(());
        }
    };
    let table = execution.table(table).ok_or_else(|| {
        ClusterError::InvalidTransfer(
            "table row is absent from signed execution metadata".to_owned(),
        )
    })?;
    if let Some(vectors) = vectors {
        for vector in vectors {
            let field = table
                .fields
                .iter()
                .find(|field| field.name == vector.field)
                .ok_or_else(|| {
                    ClusterError::InvalidTransfer(
                        "table vector field is absent from signed execution metadata".to_owned(),
                    )
                })?;
            let definition = crate::tables::decode_field_def(&field.name, &field.definition);
            let crate::tables::FieldType::Vector(dimensions) = definition.field_type else {
                return invalid("table vector sidecar belongs to a non-vector field");
            };
            let DumpValue::Vector(values, _, _) = &vector.value else {
                return invalid("table vector sidecar must contain a vector");
            };
            if values.len() != dimensions {
                return invalid("table vector sidecar dimensions do not match signed metadata");
            }
        }
    }
    Ok(())
}

pub(crate) fn table_row_key(table: &str, primary_key: &[u8]) -> Result<Vec<u8>, ClusterError> {
    let primary_key = std::str::from_utf8(primary_key)
        .map_err(|_| ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned()))?;
    Ok(format!("_t:{table}:row:{primary_key}").into_bytes())
}

pub(crate) fn table_vector_key(
    table: &str,
    field: &str,
    primary_key: &[u8],
) -> Result<Vec<u8>, ClusterError> {
    validate_field(field)?;
    let primary_key = std::str::from_utf8(primary_key)
        .map_err(|_| ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned()))?;
    Ok(format!("_t:{table}:vec:{field}:{primary_key}").into_bytes())
}

fn validate_field(field: &str) -> Result<(), ClusterError> {
    if field.is_empty()
        || field.len() > MAX_RECORD_NAME_BYTES
        || !field
            .chars()
            .all(|character| character.is_alphanumeric() || character == '_')
    {
        return invalid("table vector field is invalid");
    }
    Ok(())
}

fn validate_expiry(expires_at_ms: Option<i64>) -> Result<(), ClusterError> {
    if expires_at_ms.is_some_and(|deadline| deadline <= 0) {
        return invalid("transfer expiry deadline must be positive");
    }
    Ok(())
}

fn validate_table_hash(value: &DumpValue) -> Result<(), ClusterError> {
    let DumpValue::Hash(pairs, expiries) = value else {
        return invalid("table-row transfer value must be a hash");
    };
    let mut fields = HashSet::with_capacity(pairs.len());
    for (field, _) in pairs {
        if !fields.insert(field.as_str()) {
            return invalid("table-row transfer value contains duplicate fields");
        }
    }
    let mut expiring = HashSet::with_capacity(expiries.len());
    for (field, deadline) in expiries {
        if *deadline <= 0 || !fields.contains(field.as_str()) || !expiring.insert(field.as_str()) {
            return invalid("table-row field expiry is invalid");
        }
    }
    Ok(())
}

fn write_expiry(writer: &mut impl Write, expires_at_ms: Option<i64>) -> std::io::Result<()> {
    writer.write_all(&expires_at_ms.unwrap_or(-1).to_be_bytes())
}

fn read_expiry(reader: &mut impl Read) -> Result<Option<i64>, ClusterError> {
    match i64::from_be_bytes(read_array(reader)?) {
        -1 => Ok(None),
        deadline if deadline > 0 => Ok(Some(deadline)),
        _ => invalid("transfer expiry deadline is invalid"),
    }
}

fn write_name(writer: &mut impl Write, value: &str) -> Result<(), ClusterError> {
    if value.len() > MAX_RECORD_NAME_BYTES {
        return invalid("transfer record name is too large");
    }
    write_bytes(writer, value.as_bytes())?;
    Ok(())
}

fn read_name(reader: &mut impl Read) -> Result<String, ClusterError> {
    String::from_utf8(read_bytes(reader, MAX_RECORD_NAME_BYTES)?)
        .map_err(|_| ClusterError::InvalidTransfer("transfer record name is not UTF-8".to_owned()))
}

fn write_bytes(writer: &mut impl Write, value: &[u8]) -> Result<(), ClusterError> {
    let length = u32::try_from(value.len()).map_err(|_| {
        ClusterError::InvalidTransfer("transfer byte string is too large".to_owned())
    })?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(value)?;
    Ok(())
}

fn read_bytes(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>, ClusterError> {
    let length = read_u32(reader)? as usize;
    if length > maximum {
        return invalid("transfer byte string exceeds its size limit");
    }
    let mut value = vec![0_u8; length];
    reader.read_exact(&mut value)?;
    Ok(value)
}

fn write_u32(writer: &mut impl Write, value: usize) -> Result<(), ClusterError> {
    let value = u32::try_from(value)
        .map_err(|_| ClusterError::InvalidTransfer("transfer count is too large".to_owned()))?;
    writer.write_all(&value.to_be_bytes())?;
    Ok(())
}

fn read_u8(reader: &mut impl Read) -> Result<u8, ClusterError> {
    Ok(read_array::<1>(reader)?[0])
}

fn read_u16(reader: &mut impl Read) -> Result<u16, ClusterError> {
    Ok(u16::from_be_bytes(read_array(reader)?))
}

fn read_u32(reader: &mut impl Read) -> Result<u32, ClusterError> {
    Ok(u32::from_be_bytes(read_array(reader)?))
}

fn read_u64(reader: &mut impl Read) -> Result<u64, ClusterError> {
    Ok(u64::from_be_bytes(read_array(reader)?))
}

fn read_array<const LENGTH: usize>(reader: &mut impl Read) -> Result<[u8; LENGTH], ClusterError> {
    let mut value = [0_u8; LENGTH];
    reader.read_exact(&mut value)?;
    Ok(value)
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}

#[cfg(test)]
#[path = "transfer_record_tests.rs"]
mod tests;
