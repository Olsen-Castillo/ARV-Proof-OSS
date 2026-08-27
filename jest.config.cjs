module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/reference/typescript/arv'],
  testMatch: ['**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.json' }]
  },
  maxWorkers: 1,
  verbose: false
};
