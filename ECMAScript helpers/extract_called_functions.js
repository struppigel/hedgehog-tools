const fs = require('fs');
const types = require('@babel/types');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const commander = require('commander');

const beautifyOpts = {
  comments: false,
  minified: false,
  concise: false,
}

/**
 * Extract called functions and the used assignments not in functions recursively
 */

if (require.main === module) {
  main();
}

function main() {

  commander
    .version('0.1','-v, --version')
    .usage('node.exe extract_called_functions.js -f <sample> -s <startnode>')
    .option('-f, --file <value>', 'The file to deobfuscate')
    .option('-s --start <value>', 'The function name where to start extracting the called functions')
    .parse(process.argv);

  const options = commander.opts();
  printHints(options);
  if(!options.file || !options.start) return;
  const infile = options.file;

  const script = fs.readFileSync(infile, 'utf-8');
  const AST = parser.parse(script, {});
  const outfile = infile + ".extracted";

  extractFunctionsAndAssignmentsNotInFunctions(AST, options);

  const codeLayer1 = generate(AST, beautifyOpts).code;
  fs.writeFileSync(outfile, codeLayer1);
  console.log("the code was saved to " + outfile);
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
      console.warn('please provide a start function with -s')
    }
  }

function extractFunctionsAndAssignmentsNotInFunctions(AST, options){
    const startNodes = [options.start];
    console.log('Start function ' + startNodes);
    const ids = findIdentifiersInNodes(AST, startNodes);
  
    const functionDeclarations = filterFunctionsFromIds(AST, ids);
    const varAssignmentsNotInFunctions = filterAssignmentsNotInFunctionsFromIds(AST, ids, startNodes[0]); 
  
    const functionNames = functionDeclarations.map((f) => f.id.name);
    console.log('Called functions found: ' + functionNames);
  
    AST.program.body = varAssignmentsNotInFunctions.concat(functionDeclarations); 
    
  }

  /**
 * Filter all functions from the list of identifiers
 * @param {object} AST the abstract syntax tree
 * @param {string[]} identifierList list of identifier names
 * @returns list of function nodes for those functions that have a name in the identifierList
 */
function filterFunctionsFromIds(AST, identifierList){
    const funs = [];
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
  
  
function filterAssignmentsNotInFunctionsFromIds(AST, ids, startNodeName){
    const assigns = [];
    const findFunctionNodeVisitor = {
      FunctionDeclaration(path) {
        if(path.node.id.name == startNodeName){
          
          for(const statement of path.parentPath.node.body){ // search in main body for assignments
            if(statement.type == "ExpressionStatement" 
            && statement.expression.type == "AssignmentExpression"
            && ids.includes(statement.expression.left.name)
            ){
              assigns.push(statement);
            }
            // search also in if statement blocks for assignments, see 08f06fc48fe8d69e4ab964500150d1b2f5f4279fea2f76fdfcefd32266dfa1af
            if(statement.type == "IfStatement" && statement.consequent.body !== undefined){ 
              for(const ifbodyNode of statement.consequent.body){
                if(ifbodyNode.type == "ExpressionStatement" 
                && ifbodyNode.expression.type == "AssignmentExpression"
                && ids.includes(ifbodyNode.expression.left.name)
                ){
                  assigns.push(ifbodyNode);
                }
              }
            }
          }
          path.stop();
        }
      }
    }
  
    traverse(AST,findFunctionNodeVisitor);
    return assigns;
}

/**
 * Recursively find all identifiers that are part of functions or assignments in the nodeNameList
 * @param {object} AST the abstract syntax tree
 * @param {string[]} nodeNameList functions that should be traversed for identifiers
 * @param {string[]} ignoreList functions with names on this list are ignored
 * @param {number} maxdepth maximum number of recursions
 * @returns list of identifiers recursively used by the function and its called functions
 */
function findIdentifiersInNodes(AST, nodeNameList, ignoreList = [], maxdepth = 500){
    let identifiers = [];
    for (let currNode of nodeNameList) {
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
 * for the functions and assignments provided in nodeName find all identifiers
 * @param {object} AST the abstract syntax tree
 * @param {string} nodeName function name
 * @returns list of identifiers
 */
function findIdentifiersInNode(AST, nodeName){

    const visitedIds = [];
    const collectIdentifiersVisitor = {
      Identifier(path){
        const foundName = path.node.name;
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
      },
    }
    const assignFinderVisitor = {
    AssignmentExpression(path){
        if(path.node.left.name == nodeName){
          const { scope, node } = path
          scope.traverse(node, collectIdentifiersVisitor, this);
          path.stop();
        }
      }
    }
    // functions first because we need to keep those nodes instead of the assignments to functions
    traverse(AST, nodeFinderVisitor); // collect identifiers from functions
    traverse(AST, assignFinderVisitor); // collect identifiers from assignment expressions
    return visitedIds;
  }
