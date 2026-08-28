declare module "sql.js" {
  type SqlJsConfig = {
    locateFile?: (file: string) => string;
  };

  type SqlJsResult = {
    columns: string[];
    values: unknown[][];
  };

  type SqlJsDatabase = {
    exec(sql: string): SqlJsResult[];
    close(): void;
  };

  type SqlJsStatic = {
    Database: new (data?: Uint8Array) => SqlJsDatabase;
  };

  const initSqlJs: (config?: SqlJsConfig) => Promise<SqlJsStatic>;
  export default initSqlJs;
}
