#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const isLocal = process.argv.includes('--local');
const agentBaseDir = isLocal ? process.cwd() : os.homedir();

const targetSkillDir = path.join(agentBaseDir, '.agents', 'skills', 'tdd-remediation');
const targetWorkflowDir = path.join(agentBaseDir, '.agents', 'workflows');
const targetTestDir = path.join(process.cwd(), '__tests__', 'security');

console.log(`Installing TDD Remediation Skill (${isLocal ? 'Local' : 'Global'})...`);

// 1. Install the Skill
if (!fs.existsSync(targetSkillDir)) {
  fs.mkdirSync(targetSkillDir, { recursive: true });
}

// Copy the specific skill files and directories
const filesToCopy = ['SKILL.md', 'prompts', 'templates'];
for (const item of filesToCopy) {
  const sourcePath = path.join(__dirname, item);
  const targetPath = path.join(targetSkillDir, item);
  if (fs.existsSync(sourcePath)) {
    fs.cpSync(sourcePath, targetPath, { recursive: true });
  }
}

// 2. Scaffold the security-tests directory
if (!fs.existsSync(targetTestDir)) {
  fs.mkdirSync(targetTestDir, { recursive: true });
  console.log(`Created security test directory at ${targetTestDir}`);
}

const sourceTestFile = path.join(__dirname, 'templates', 'sample.exploit.test.js');
const targetTestFile = path.join(targetTestDir, 'sample.exploit.test.js');

if (!fs.existsSync(targetTestFile)) {
  fs.copyFileSync(sourceTestFile, targetTestFile);
  console.log(`Scaffolded boilerplate exploit test at ${targetTestFile}`);
}

// 3. Install the workflow shortcode
if (!fs.existsSync(targetWorkflowDir)) {
  fs.mkdirSync(targetWorkflowDir, { recursive: true });
}

const sourceWorkflowFile = path.join(__dirname, 'workflows', 'tdd-audit.md');
const targetWorkflowFile = path.join(targetWorkflowDir, 'tdd-audit.md');

if (fs.existsSync(sourceWorkflowFile)) {
  fs.copyFileSync(sourceWorkflowFile, targetWorkflowFile);
  console.log(`Installed shortcode workflow at ${targetWorkflowFile}`);
}

console.log(`Successfully installed TDD Remediation skill to ${targetSkillDir}`);
console.log('You can now use `/tdd-audit` in your Anti-Gravity chat!');
