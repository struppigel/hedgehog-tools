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
 * Extracts, unpacks and beautifies 3 layers of GootLoader's JavaScript code 
 * using abstract syntax tree parsing via babel.
 * Extracts the C2s of the final layer and prints them to console.
 * Resulting unpacked code is saved to transpiled.layer[1|2|3].js
 *
 * Sample: 1bc77b013c83b5b075c3d3c403da330178477843fc2d8326d90e495a61fbb01f
 * 
 */

if (require.main === module) {
  main();
}

function main() {

  commander
    .version('0.1','-v, --version')
    .usage('node.exe gootloader_decoder.js -f <sample> [-s <startnode>]')
    .option('-f, --file <value>', 'The file to deobfuscate')
    .option('-s --start <value>', 'The function name where the malware code starts')
    .parse(process.argv);

  const options = commander.opts();
  printHints(options);
  if(!options.file) return;
  const gootfile = options.file;

  console.log("\n----------------- Layer 1 -----------------\n");

  const script = fs.readFileSync(gootfile, 'utf-8');
  const AST = parser.parse(script, {})

  transpileLayer1(AST, options, "transpiled.layer1.js");
  console.log("\n----------------- Layer 2 -----------------\n");
  const layer2AST = transpileLayer2(AST, "transpiled.layer2.js");
  console.log("\n----------------- Layer 3 -----------------\n");
  const layer3AST = transpileLayer3(layer2AST, "transpiled.layer3.js");
  console.log("\n----------------- C2s -----------------\n");
  const c2list = extractC2s(layer3AST);
  for(const c2 of c2list){
    console.log(c2);
  }
}

function extractC2s(layer3AST){
  let c2list = [];
  const findWWWStringVisitor = {
    StringLiteral(path) {
      const v = path.node.value;
      if(v.startsWith('www.')) {
         c2list.push(v);
      }
    }
  }
  traverse(layer3AST,findWWWStringVisitor);
  return c2list;
}

function transpileLayer3(layer2AST, outfile){
  const decryptedCodeL3 = decryptCodeLayer3(layer2AST);
  const layer3AST = beautifyAndWriteCodeToFile(decryptedCodeL3, outfile);
  return layer3AST;
}

function transpileLayer2(AST, outfile){
  const decryptedCodeL2 = decryptCodeLayer2(AST);
  const layer2AST = beautifyAndWriteCodeToFile(decryptedCodeL2, outfile);
  return layer2AST;
}

function transpileLayer1(AST, options, outfile){
  const startNodes = options.start ? [options.start] : findPotentialStartNodes(AST);
  console.log('Start nodes found ' + startNodes);
  const ids = findIdentifiersInNodes(AST, startNodes);
  const functionDeclarations = filterFunctionsFromIds(AST, ids);
  const functionNames = functionDeclarations.map((f) => f.id.name);
 
  console.log('functions found: ' + functionNames);

  AST.program.body = functionDeclarations; 
  const codeLayer1 = generate(AST, beautifyOpts).code;
  fs.writeFileSync(outfile, codeLayer1);
  console.log("the code was saved to " + outfile);
}

function beautifyAndWriteCodeToFile(code, outfile) {
  const ast = parser.parse(code);
  concatStringLiterals(ast);
  const beautifiedCode = generate(ast, beautifyOpts).code;
  fs.writeFileSync(outfile, beautifiedCode);
  console.log("the code was saved to " + outfile);
  return ast;
}

/**
 * decode and return string representation of the decrypted code from layer 3
 * @param {*} layer2AST 
 * @returns 
 */
function decryptCodeLayer3(layer2AST){
  const encryptedBlob = extractBiggestStringLiteralValue(layer2AST);
  const decryptedCode = gootloaderDecode(encryptedBlob);
  // wrap into function declaration to allow parsing
  return 'function gldr(){ ' + decryptedCode + ' }'; 
}

/**
 * decrypt and return string representation of the decrypted code from layer 2
 * @param {*} layer1AST 
 * @returns 
 */
function decryptCodeLayer2(layer1AST){
  const encryptedVarNode = findLayer1EncryptedCodeBuilder(layer1AST);
  console.log('identified encrypted data node: ' + encryptedVarNode.left.name);
  const encryptedBlob = buildEncryptedString(layer1AST, encryptedVarNode);
  const key = extractKey(layer1AST, encryptedVarNode.left.name);
  console.log('extracted key: ' + key);
  return gootloaderDecrypt(gootloaderDecode(encryptedBlob), key)[1];
}

/**
 * Find and extract the decryption key based on variable name containing the encrypted blob
 * music2 = "wjutmzH"; --> we want this
 * yet7 = plant7(use45(finish7), music2); --> we search this
 * 
 * @param {object} AST 
 * @param {*} encryptedVarNode 
 * @returns 
 */
function extractKey(AST, encryptVarName){
  let key = '';
  let keyName = '';

  const findKeyVarNameVisitor = {
    CallExpression(path) {
      if(path.node.arguments.length == 1 
        && path.node.arguments[0].name == encryptVarName) {
          keyName = path.parentPath.node.arguments[1].name; // get name of second argument from parent call
          path.stop();
      }
    }
  }

  const findKeyVarContentVisitor = {
    AssignmentExpression(path) {
      if(path.node.left.name == keyName){
        key = path.node.right.value;
        path.stop();
      }
    }
  }

  traverse(AST,findKeyVarNameVisitor);
  traverse(AST,findKeyVarContentVisitor);
  return key;
}

/**
 * Gootloaders decryption routine
 * @param {*} encryptedStr 
 * @param {*} key 
 * @returns 
 */
function gootloaderDecrypt(encryptedStr, key) {
  const decrypted = [];
  let offset = 0;
  let keylen = key.length;
  for (let idx = 0; idx <= encryptedStr.length - keylen; idx++) {
    if (encryptedStr.substr(idx, keylen) == key) {
      decrypted[decrypted.length] = encryptedStr.substr(offset, idx - offset);
      offset = idx + keylen;
    }
  }
  decrypted[decrypted.length] = encryptedStr.substr(offset);
  return decrypted;
}

/**
 * Gootloaders decoding routine
 * @param {*} encodedStr 
 * @returns 
 */
function gootloaderDecode(encodedStr) {

  function flip(somestr, somechar, idx) {
    if (idx % 2) return somestr + somechar;
    else return somechar + somestr;
  }
  let idx = 0;
  let result = "";
  while (idx < 2704) {
    const charSub = encodedStr.substr(idx,1);
    result = flip(result, charSub, idx);
    idx++;
  }
  return result;
}

/**
 * Find largest String in a StringLiteral and return it.
 * @param {*} AST 
 * @returns largest string
 */
function extractBiggestStringLiteralValue(AST){
  let str = '';
  const findBiggestStringVisitor = {
    StringLiteral(path) {
      const v = path.node.value;
      if(str.length < v.length) {
         str = v;
      }
    }
  }
  traverse(AST,findBiggestStringVisitor);
  return str;
}

/**
 * Modify AST so that the encryptedVarNode consists of one assignment to a StringLiteral. 
 * Returns the value of this string.
 * 
 * @param {*} AST 
 * @param {*} encryptedVarNode 
 * @returns 
 */
function buildEncryptedString(AST, encryptedVarNode) {
  // this call will change AST so that the encryptedVarNode will be assigned a single StringLiteral
  replaceIdentifiersWithStringLiteral(AST, encryptedVarNode);
  // that means the right side of the assignment operation contains the string
  return encryptedVarNode.right.value;
}

/**
 * Based on the encryptedVarNode, which is an assignment expression, replace all the identifiers on 
 * the right side of the assignment with their actual String literals.
 * 
 * E.g. finish7 = run0 + milk0 + plural6 + similar6 + exact1 + house4 + miss8 + oxygen1 + dream6 + believe22 + said7 + map5;
 * becomes finish7 = 'actualstring ...';
 * 
 * @param {*} AST 
 * @param {*} encryptedVarNode 
 */
function replaceIdentifiersWithStringLiteral(AST, encryptedVarNode){

  function getIdentifiersFromNode(node){
    if(node.type == "AssignmentExpression") return getIdentifiersFromNode(node.right);
    else if(node.type == "Identifier") return [node.name];
    else if(node.type == "BinaryExpression") {
      return getIdentifiersFromNode(node.left).concat(getIdentifiersFromNode(node.right));
    }
    else return [];
  }

  function getIdentifiersFromNodes(listOfNodes) {
    let ids = [];
    for(const idNode of listOfNodes){
      ids = ids.concat(getIdentifiersFromNode(idNode));
    }
    return ids;
  }

  function findAssignmentNodesForNames(namesList){
    const assignmentNodes = [];
    const findAssignmentNodeVisitor = {
      AssignmentExpression(path) {
        if(namesList.includes(path.node.left.name)) {
            assignmentNodes.push(path.node);
        }
      }
    }
    traverse(AST,findAssignmentNodeVisitor);
    return assignmentNodes;
  }

  function buildStringAssignMap(assignNodes){
    const arr = assignNodes.filter((n) => n.type == "AssignmentExpression" && n.right.type == "StringLiteral");
    return new Map(arr.map((n) => [n.left.name, n.right.value]));
  }

  // check for each node if it is a string assignment and if so, delete
  function deleteStringAssignmentNodes(nodes){
    const delStringAssignmentsVisitor = {
      AssignmentExpression(path){
        if(path.node.right.type == "StringLiteral" && nodes.includes(path.node)) {
          path.remove();
        }
      }
    };
    traverse(AST, delStringAssignmentsVisitor);
  }

  function replaceIdentifiersWithStringLiterals(strAssignMap){
    const replaceNodeVisitor = {
      Identifier(path) {
        if(strAssignMap.has(path.node.name)) {
            const newNode = types.stringLiteral(strAssignMap.get(path.node.name));
            path.replaceWith(newNode);
        }
      }
    }
    traverse(AST,replaceNodeVisitor);
  }

  const ids = getIdentifiersFromNode(encryptedVarNode);
  const assignmentNodes = findAssignmentNodesForNames(ids);
  
  const ids_secondpass = getIdentifiersFromNodes(assignmentNodes);
  const stringAssignNodes = findAssignmentNodesForNames(ids_secondpass);

  const strAssignMap = buildStringAssignMap(stringAssignNodes);
  deleteStringAssignmentNodes(stringAssignNodes);
  replaceIdentifiersWithStringLiterals(strAssignMap);
  concatStringLiterals(AST);
  // second pass (for improvement make this recursive)
  const secondStrAssignMap = buildStringAssignMap(assignmentNodes);
  deleteStringAssignmentNodes(assignmentNodes);
  replaceIdentifiersWithStringLiterals(secondStrAssignMap);
  concatStringLiterals(AST);
}

/**
 * Concatenate string literals in the whole AST
 * if the input is "a" + "b" + "c"
 * the output will be "abc"
 * 
 * @param {object} AST the abstract syntax tree
 */
function concatStringLiterals(AST){
  const concatStringLiteralsVisitor = {
    BinaryExpression(path) {
      if(path.node.left.type == "BinaryExpression") {
          path.traverse(concatStringLiteralsVisitor);
      }
      if(path.node.left.type == "StringLiteral" && path.node.right.type == "StringLiteral"){
        const resval = path.node.left.value + path.node.right.value;
        path.replaceWith(types.stringLiteral(resval));
      }
    }
  }
  traverse(AST,concatStringLiteralsVisitor);
}

/**
 * Find the node that holds the encrypted string of the first code layer
 * 
 * @param {object} AST the abstract syntax tree
 * @returns node that gets assigned the encrypted string for the next layer
 */
function findLayer1EncryptedCodeBuilder(AST) {
  let matchingNode = 'not found';
  let maxCount = -1;

  function countBinaryExpressionChainWithIdentifiers(node){
    if(node.left.type == "BinaryExpression"
    && node.right.type == "Identifier") {
      return 1 + countBinaryExpressionChainWithIdentifiers(node.left);
    } else return 0;
  }

  let findEncryptedCodeBuilderVisitor = {
    AssignmentExpression(path) {
      if(path.node.right.type == "BinaryExpression" 
      && path.node.right.right.type == "Identifier" ) {
        let cnt = countBinaryExpressionChainWithIdentifiers(path.node.right);
        if(cnt > maxCount) { 
          maxCount = cnt;
          matchingNode = path.node; 
        }
      }
    }
  }
  traverse(AST, findEncryptedCodeBuilderVisitor);
  return matchingNode;
}

/**
 * Find all potential start nodes by matching functions calls that have one argument which is a NumericLiteral, like so: note7(3696)
 * This will extract more (malware) nodes than just the start node, but as long as the start node is part of this list, 
 * the extractor will get all the functions.
 * 
 * @param {object} AST the abstract syntax tree
 */
function findPotentialStartNodes(AST){
  const matchingNodes = [];
  const findStartNodeVisitor = {
    CallExpression(path) {
      if(
        path.node.arguments.length == 1                  // exactly one argument
        && path.node.arguments[0].type == 'NumericLiteral'  // argument is a numeric literal
        && typeof path.node.callee.name !== 'undefined'     // function has a name
        ) {
          let name = path.node.callee.name;
          if(!matchingNodes.includes(name)) matchingNodes.push(name);
      }
    }
  }
  traverse(AST,findStartNodeVisitor);
  return matchingNodes;
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
    console.log('parser will try to find the starting point, to set another one, use the option -n')
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

/**
 * for the function provided in nodeName find all identifiers
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
    }
  }
  
  traverse(AST, nodeFinderVisitor);
  
  return visitedIds;
}
