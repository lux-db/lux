import { describe, expect, test } from "bun:test";
import { encodeResp, parseResp } from "./resp";

describe("benchmark RESP framing", () => {
	test("encodes commands", () => {
		expect(encodeResp(["GET", "key"]).toString()).toBe(
			"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n",
		);
	});

	test("parses nested and partial replies", () => {
		const complete = Buffer.from("*2\r\n$8\r\nkmessage\r\n:1\r\n");
		expect(parseResp(complete)).toEqual({
			value: ["kmessage", 1],
			end: complete.length,
		});
		expect(parseResp(complete.subarray(0, complete.length - 1))).toBeNull();
	});
});
