import { describe, expect, it } from "vitest";
import { EditorState } from "@codemirror/state";

import { toCodemirrorDiagnostics } from "./diagnostics";

const stateFor = (doc: string) => EditorState.create({ doc });

describe("toCodemirrorDiagnostics", () => {
  it("maps a line-anchored error onto the correct character range", () => {
    const state = stateFor("a: 1\nb: 2\nc: 3");
    const diagnostics = toCodemirrorDiagnostics(state, [
      { line: 2, role: null, tool: null, message: "bad value" },
    ]);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      severity: "error",
      message: "bad value",
      from: 5, // start of line 2 ("b")
      to: 9, // end of line 2 ("2")
    });
  });

  it("prefixes role-scoped errors with the role name", () => {
    const state = stateFor("roles:\n  support: {}\n");
    const [d] = toCodemirrorDiagnostics(state, [
      {
        line: 2,
        role: "support",
        tool: null,
        message: "must have at least one tool",
      },
    ]);
    expect(d.message).toBe("support: must have at least one tool");
  });

  it("drops errors without a line number (role-level / whole-document)", () => {
    const state = stateFor("a: 1");
    const diagnostics = toCodemirrorDiagnostics(state, [
      {
        line: null,
        role: "support",
        tool: null,
        message: "role not referenced",
      },
      { line: null, role: null, tool: null, message: "missing default_policy" },
    ]);
    expect(diagnostics).toEqual([]);
  });

  it("clamps a line number past the doc end to the last line", () => {
    // Validator may report a line that no longer exists if the user typed
    // since — clamp instead of throwing on `doc.line(out_of_range)`. No
    // trailing newline here so `doc.lines === 1` and the clamp lands on
    // a non-empty line we can assert range-of-text on.
    const state = stateFor("only one line");
    const [d] = toCodemirrorDiagnostics(state, [
      { line: 99, role: null, tool: null, message: "phantom" },
    ]);
    expect(d.from).toBe(0);
    expect(d.to).toBe("only one line".length);
  });

  it("ignores errors with line=0 (1-indexed lines per server contract)", () => {
    const state = stateFor("a: 1\n");
    const diagnostics = toCodemirrorDiagnostics(state, [
      { line: 0, role: null, tool: null, message: "should not happen" },
    ]);
    expect(diagnostics).toEqual([]);
  });
});
