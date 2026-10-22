import "@kusto/language-service-next/bridge.js";
import "@kusto/language-service-next";
import schemas from "../../detections/schemas.json" with { type: "json" };

export const KQL_SCHEMAS = schemas;
const language = globalThis.Kusto.Language;
const toArray = (list) => globalThis.Bridge.toArray(list);
const checkedSchemas = new Set();

export function compileQuery(query, platform, includedTables = Object.keys(schemas[platform] ?? {})) {
  if (!Object.hasOwn(schemas, platform)) throw new Error(`Unknown KQL platform: ${platform}.`);
  const tables = includedTables.map((name) => {
    if (!Object.hasOwn(schemas[platform], name)) throw new Error(`Unknown schema fixture: ${platform}/${name}.`);
    const key = `${platform}/${name}`;
    if (!checkedSchemas.has(key)) {
      const declaration = language.KustoCode.ParseAndAnalyze(`datatable${schemas[platform][name]}[]`, language.GlobalState.Default);
      if (toArray(declaration.GetSyntaxDiagnostics()).length
          || toArray(declaration.GetDiagnostics()).some((diagnostic) => diagnostic.Severity === "Error")) {
        throw new Error(`Invalid compiler schema fixture: ${key}.`);
      }
      checkedSchemas.add(key);
    }
    return new language.Symbols.TableSymbol.$ctor7(name, schemas[platform][name], "offline contract fixture; not collected telemetry");
  });
  const globals = language.GlobalState.Default.WithDatabase(new language.Symbols.DatabaseSymbol.ctor("OfflineSchemaFixture", tables));
  const code = language.KustoCode.ParseAndAnalyze(query, globals);
  return {
    syntax: toArray(code.GetSyntaxDiagnostics()),
    errors: toArray(code.GetDiagnostics()).filter((diagnostic) => diagnostic.Severity === "Error"),
    columns: code.ResultType?.Columns ? toArray(code.ResultType.Columns).map((column) => column.Name) : [],
  };
}
