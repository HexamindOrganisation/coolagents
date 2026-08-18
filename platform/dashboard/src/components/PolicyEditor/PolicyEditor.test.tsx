/**
 * Smoke tests for the policy editor wrapper. CodeMirror's own test suite
 * covers the edit lifecycle; here we only verify the wiring around it
 * (initial value renders, lint gutter is mounted, readOnly is honored).
 *
 * We avoid driving the contenteditable surface via DOM events — that's
 * fragile under jsdom because CodeMirror relies on browser composition
 * APIs that jsdom only partially implements. The onChange forwarding
 * is a one-line passthrough to `<CodeMirror onChange={onChange} />`,
 * which @uiw/react-codemirror tests on its own.
 */
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";

import { PolicyEditor } from "./PolicyEditor";

describe("PolicyEditor", () => {
  it("renders the initial value into the editor surface", () => {
    const { container } = render(
      <PolicyEditor value={"version: 1\nroles: {}"} onChange={() => {}} />,
    );
    // CodeMirror tokenises into spans inside `.cm-content`. We don't care
    // about the exact DOM shape — only that the text reaches the document.
    expect(container.textContent).toContain("version: 1");
    expect(container.textContent).toContain("roles: {}");
  });

  it("renders the lint gutter so diagnostics have somewhere to anchor", () => {
    const { container } = render(
      <PolicyEditor
        value={"a: 1\n"}
        onChange={() => {}}
        diagnostics={[{ line: 1, role: null, tool: null, message: "bad" }]}
      />,
    );
    // `.cm-gutter-lint` is the gutter class that `lintGutter()` adds.
    expect(container.querySelector(".cm-gutter-lint")).not.toBeNull();
  });

  it("respects readOnly by exposing aria-readonly on the editor", () => {
    const { container } = render(
      <PolicyEditor value="a: 1" onChange={() => {}} readOnly />,
    );
    expect(container.querySelector('[aria-readonly="true"]')).not.toBeNull();
  });
});
