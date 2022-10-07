const path = require('path');
const { pathsToModuleNameMapper } = require('ts-jest');
const { compilerOptions } = require('./tsconfig');

/** @type {import('ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
  preset: 'ts-jest',
  rootDir: '.',
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths, { prefix: __dirname }),
  testPathIgnorePatterns: [],
  'automock': false,
  'resetMocks': false,
};
