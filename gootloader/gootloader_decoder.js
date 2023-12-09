const fs = require('fs');
const types = require('@babel/types');
const parser = require('@babel/parser');
const { functionDeclaration } = require('@babel/types');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const commander = require('commander');

const beautify_opts = {
  comments: false,
  minified: false,
  concise: false,
}

/**
 * Extracts functions from JavaScript code that are called or referenced starting from a given function. 
 * The functions are collected recursively using an abstract syntax tree of the given code.
 * Tested on a Gootkit sample where the relevant malware functions are buried in 10000 lines of code.
 *
 * Sample: 1bc77b013c83b5b075c3d3c403da330178477843fc2d8326d90e495a61fbb01f
 * 
 * This might become a full deobfuscator later.
 */

if (require.main === module) {
  main();
}

function main() {

  commander
    .version('0.1','-v, --version')
    .usage('node.exe gootloader_decoder.js -f <sample> -o <output> -n <startnode>')
    .option('-f, --file <value>', 'The file to deobfuscate')
    .option('-s --start <value>', 'The function name where the malware code starts')
    .option('-o --outfile <value>', 'The file with the transpiled code')
    .parse(process.argv);

  const options = commander.opts();
  printHints(options);
  if(!options.file) return;
  let gootfile = options.file;
  let startNode = options.start ? options.start : 'note7';
  let outfile = options.outfile ? options.outfile : 'transpiled.js';

  console.log("started parsing ...\n");

  const script = fs.readFileSync(gootfile, 'utf-8');
  const AST = parser.parse(script, {})

  let ids = findIdentifiersInNodes(AST, [startNode]);
  let functionDeclarations = filterFunctionsFromIds(AST, ids);
  let functionNames = functionDeclarations.map((f) => f.id.name);
  
  console.log('functions found: ' + functionNames);
  console.log('extracting those functions and building transpiled code ...\n');

  AST.program.body = functionDeclarations;
  const final_code = generate(AST, beautify_opts).code;
  fs.writeFileSync(outfile, final_code);
  
  console.log("done transpiling!");
  console.log("the final code was saved to " + outfile);
}

/**
 * Print some stuff to console to help the user.
 * @param {*} options 
 * @returns 
 */
function printHints(options) {
  if(!options.file) {
    console.warn('please provide a file to deobfuscate with -f');
    return;
  }
  
  if(!options.start) {
    console.log('using note7 as starting point, to set another one, use the option -n')
  }

  if(!options.outfile) {
    console.log('using transpiled.js as output filename, to set another one use the option -o')
  }
}

/**
 * Removes all functions whose names are in the functionToClean list.
 * @param {object} AST the abstract syntax tree (will be modified)
 * @param {string[]} functionToClean function names to with functions to remove
 */
function cleanupFunctions(AST, functionToClean){
  const keepOnlyListedFunctionsVisitor = {
    FunctionDeclaration(path){
      if(!functionsToClean.includes(path.node.id.name)) {
        path.remove();
      }
    }
  };
  traverse(AST, keepOnlyListedFunctionsVisitor);
}

/**
 * Recursively find all identifiers that are part of function in the nodeNameList
 * @param {object} AST the abstract syntax tree
 * @param {string[]} nodeNameList functions that should be traversed for identifiers
 * @param {string[]} ignoreList functions with names on this list are ignored
 * @param {number} maxdepth maximum number of recursions
 * @returns list of identifiers recursively used by the function and its called functions
 */
function findIdentifiersInNodes(AST, nodeNameList, ignoreList = [], maxdepth = 500){
  let identifiers = [];
  for (let i = 0; i < nodeNameList.length; i++) {
    let currNode = nodeNameList[i];
    if(!ignoreList.includes(currNode)){
      let foundNodes = findIdentifiersInNode(AST, currNode);
      if(typeof foundNodes === 'undefined' || foundNodes.length == 0) continue;
      identifiers = identifiers.concat(foundNodes);
      ignoreList.push(currNode);
    } 
  }
  if (identifiers.length == 0) return [];
  if (maxdepth == 0) {
    console.warn('max recursion depth reached!');
    return identifiers;
  }
  return identifiers.concat(findIdentifiersInNodes(AST, identifiers, ignoreList, maxdepth-1));
}

/**
 * Filter all functions from the list of identifiers
 * @param {object} AST the abstract syntax tree
 * @param {string[]} identifierList list of identifier names
 * @returns list of function nodes for those functions that have a name in the identifierList
 */
function filterFunctionsFromIds(AST, identifierList){
  let funs = [];
  const functionFinderVisitor = {
    FunctionDeclaration(path){
      let newFun = path.node.id.name;
      if(identifierList.includes(newFun) && !funs.includes(newFun)){
        funs.push(path.node);
      }
    }
  }
  
  traverse(AST, functionFinderVisitor);
  return funs;
}

/**
 * for the function provided in nodeName find all identifiers
 * @param {object} AST the abstract syntax tree
 * @param {string} nodeName function name
 * @returns list of identifiers
 */
function findIdentifiersInNode(AST, nodeName){

  let visitedIds = [];
  const collectIdentifiersVisitor = {
    Identifier(path){
      var foundName = path.node.name;
      if(typeof foundName === 'string' && !visitedIds.includes(foundName)) {
        visitedIds.push(foundName);
      }
    }
  }

  const nodeFinderVisitor = {
    FunctionDeclaration(path){
      if(path.node.id.name == nodeName){
        const { scope, node } = path
        scope.traverse(node, collectIdentifiersVisitor, this);
        path.stop();
      }
    }
  }
  
  traverse(AST, nodeFinderVisitor);
  
  return visitedIds;
}