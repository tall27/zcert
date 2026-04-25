import fs from 'node:fs';
import path from 'node:path';

export const ensureFileExists = (filePath: string): void => {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Required file does not exist: ${filePath}`);
  }
};

export const ensureDir = (dirPath: string): void => {
  fs.mkdirSync(dirPath, { recursive: true });
};

export const readJson = (filePath: string): unknown => {
  ensureFileExists(filePath);
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as unknown;
  } catch (error) {
    throw new Error(`Unable to parse JSON at ${filePath}: ${(error as Error).message}`);
  }
};

export const writeJson = (filePath: string, data: unknown): void => {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
};
