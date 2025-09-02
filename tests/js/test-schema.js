import fs from 'fs';
import path from 'path';
import Ajv from 'ajv/dist/2020.js';

const __dirname = path.dirname(new URL(import.meta.url).pathname);
const schemaPath = path.resolve(__dirname, '../../schemas/receipt-v1.schema.json');
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
const ajv = new Ajv({strict: false});
const validate = ajv.compile(schema);

function load(dir) {
  return fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => path.join(dir, f));
}

for (const file of load(path.resolve(__dirname, '../../schemas/vectors/valid'))) {
  const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
  if (!validate(data)) {
    console.error('expected valid but failed:', file, validate.errors);
    process.exit(1);
  }
}

for (const file of load(path.resolve(__dirname, '../../schemas/vectors/invalid'))) {
  const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
  if (validate(data)) {
    console.error('expected invalid but passed:', file);
    process.exit(1);
  }
}

console.log('all vectors ok');
