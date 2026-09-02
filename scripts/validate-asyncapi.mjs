import { Parser, fromFile } from "@asyncapi/parser";

const parser = new Parser();
const { document, diagnostics } = await fromFile(
  parser,
  "docs/asyncapi.yaml",
).parse();
const errors = diagnostics.filter((diagnostic) => diagnostic.severity === 0);

if (!document || errors.length > 0) {
  console.error(JSON.stringify(diagnostics, null, 2));
  process.exitCode = 1;
} else {
  console.log(`AsyncAPI valid (${diagnostics.length} non-error diagnostics)`);
}
