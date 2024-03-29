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

const settings = {
  quiet: false,
  no_dump: false
}

/**
 * Extracts, unpacks and beautifies up to 6 layers of GootLoader's JavaScript code 
 * using abstract syntax tree parsing via babel.
 * Extracts the C2s of the final layer and prints them to console.
 * Resulting unpacked code is saved to <sample>.layer[1|2|3|4|5|6].vir
 *
 * Test samples: 
 * 07253c4ff2a7f296cfdb6c45ddec08f61b6ecad37a30f45455df83d48c193083 --> malpedia sample, complete, has 3 layers
 * 1bc77b013c83b5b075c3d3c403da330178477843fc2d8326d90e495a61fbb01f --> complete, has 3 layers
 * 08f06fc48fe8d69e4ab964500150d1b2f5f4279fea2f76fdfcefd32266dfa1af --> complete, has 6 layers
 * 320b4d99c1f5fbc3cf1dfe593494484b1d4cb1ac7ac1f6266091e85ef51b4508 --> complete, has 6 layers
 * 445a5c6763877994206d2b692214bb4fba04f40a07ccbd28e0422cb1c21ac95b --> complete, has 6 layers
 * cbd826f59f1041065890cfe71f046e59ae0482364f1aaf79e5242de2246fb54b --> complete, has 6 layers
 * b34bcf097ad6ab0459bc6a4a8f487ca3526b6069ec01e8088fd4b00a15420554 --> complete, has 6 layers
 * 1b8b2fbdff9e4109edae317c4dd8cef7bb7877d656e97a3dd0a1e8c0c9d72b0b --> complete, has 6 layers
 * 5fe38a3b92a3c52c9d970a9a589c2210c73de0e0ecbddae71553d2b1724dc281 --> complete, has 6 layers
 */

if (require.main === module) {
  main();
}

function main() {

  commander
    .version('0.1','-v, --version')
    .usage('node.exe gootloader_decoder.js -f <sample> [-s <startnode>] [--c2s c2list.txt]')
    .option('-f, --file <value>', 'The file to deobfuscate')
    .option('-s --start <value>', 'The function name where the malware code starts, use this if the extractor fails to determine it correctly')
    .option('-c, --c2s <value>', 'Write the extracted C2s to the given text file, C2s will be appended if file exists')
    .option('-n, --no_dump', 'Don\'t dump unpacked code')
    .option('-q, --quiet', 'Only print C2 data, be quiet otherwise')
    .parse(process.argv);

  const options = commander.opts();
  settings.no_dump = options.no_dump;
  settings.quiet = options.quiet;
  printHints(options);
  if(!options.file) return;
  const gootfile = options.file;

  write("\n----------------- Layer 1 -----------------\n");

  const script = fs.readFileSync(gootfile, 'utf-8');
  const AST = parser.parse(script, {})

  transpileLayer1(AST, options, gootfile + ".layer1.vir");
  write("\n----------------- Layer 2 -----------------\n");
  const [layer2AST, constant1] = transpileLayer2(AST, gootfile + ".layer2.vir");
  write("\n----------------- Layer 3 -----------------\n");
  const layer3AST = transpileLayer3(layer2AST, gootfile + ".layer3.vir", constant1);
  
  let ioclist = extractC2s(layer3AST);
  if(ioclist.length == 0) { // no c2s found, so we need to unpack layer4 to layer6
    ioclist = extractIoCs(layer3AST);
    write("\n----------------- Layer 4 -----------------\n");
    const originalAST = parser.parse(script, {})
    const layer4AST = transpileLayer4(originalAST, layer3AST, gootfile + ".layer4.vir", constant1);
    write("\n----------------- Layer 5 -----------------\n");
    const [layer5AST, constant2] = transpileLayer5(layer4AST, gootfile + ".layer5.vir");
    write("\n----------------- Layer 6 -----------------\n");
    const layer6AST = transpileLayer6(layer5AST, gootfile + ".layer6.vir", constant2);
    ioclist = ioclist.concat(extractC2s(layer6AST));
  }
  write("\n------------------ IoCs -------------------\n");
  for(const iocEntry of ioclist){
    console.log(iocEntry);
  }
  if(options.c2s && ioclist.length > 0) {
    fs.appendFileSync(options.c2s,c2list.join('\n'));
    write('c2s written to ' + options.c2s);
  }
}

function write(str){
  if (!settings.quiet) {
    console.log(str);
  }
}

function extractIoCs(AST){
  let taskVarName = '';
  let jsFileVarName = '';
  let logVarName = '';

  const findIoCVarNameVisitor = {
    MemberExpression(path) {
      if(path.node.property.value === "GetTask" 
      && path.parentPath.node.type === "CallExpression"){
        taskVarName = path.parentPath.node.arguments[0].name;
      }
      else if(path.node.property.value === "name" 
      && path.parentPath.node.type === "AssignmentExpression"){
        jsFileVarName = path.parentPath.node.right.name;
      }
      if(jsFileVarName.length > 0 && taskVarName.length > 0) {
        path.stop();
      }
    },
    BinaryExpression(path){
      if(path.node.right.type === "StringLiteral"
        && path.node.right.value === "\\"
        && path.parentPath.node.right.type === "Identifier"){
          logVarName = path.parentPath.node.right.name;
      }
    }
  }

  traverse(AST, findIoCVarNameVisitor);
  let taskNodes = findAssignmentNodesForNames(AST, [taskVarName]);
  let taskName = taskNodes[0].right.value;
  let jsFileNodes = findAssignmentNodesForNames(AST, [jsFileVarName]);
  let jsFileName = jsFileNodes[0].right.value;
  let logVarNodes = findAssignmentNodesForNames(AST, [logVarName]);
  let logName = logVarNodes[0].right.value;

  return ["scheduled task: " + taskName, 
          "js file: " + jsFileName, 
          "log file: " + logName + '\n'];
}

function extractC2s(layer3AST){
  let c2list = [];
  const findURLStringVisitor = {
    StringLiteral(path) {
      const v = path.node.value;
      if(v.includes('www.') || v.includes('http:') || v.includes('https:')) {
        const regx = /(https?:[\/\\][\/\\]|www.)[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;
        let matches;
        let found = false;
        do {
          matches = regx.exec(v);
          if (matches) {
            c2list.push("C2: " + matches[0]);
            found = true;
          }
        } while (matches);
        if(!found){   
          console.warn('no URL matches despite initial pattern in: ' + v);
        }
      }
    }
  }
  traverse(layer3AST,findURLStringVisitor);
  return c2list;
}

function transpileLayer6(AST, outfile, decodeConstant){
  return transpileLayer3(AST, outfile, decodeConstant);
}

function transpileLayer5(AST, outfile){
  const [layer5AST, decodeConstant] = transpileLayer2(AST, outfile);
  return [layer5AST, decodeConstant];
}

function transpileLayer4(originalAST, layer3AST, outfile, decodeConstant){  
  const encryptedVarNode = findLayer4EncryptedCodeBuilder(layer3AST);
  write('found encryption node: ' + encryptedVarNode.left.name);
  
  //inserting node into old tree to have all the assignment values in one AST
  insertEncryptionNode(originalAST, encryptedVarNode); 

  const encryptedBlob = buildEncryptedString(originalAST, encryptedVarNode);
  
  const decoded = gootloaderDecode(encryptedBlob, decodeConstant);
  write("decoded " + decoded.length + " bytes");

  return beautifyAndWriteCodeToFile(decoded, outfile);
}

function transpileLayer3(AST, outfile, decodeConstant){
  const decryptedCodeL3 = decryptCodeLayer3(AST, decodeConstant);  
  const layer3AST = parser.parse(decryptedCodeL3);
  concatStringLiterals(layer3AST);
  decodeStringsLayer3(layer3AST);
  const beautifiedCode = generate(layer3AST, beautifyOpts).code;
  if(!settings.no_dump) fs.writeFileSync(outfile, beautifiedCode);
  write("the code was saved to " + outfile);

  return layer3AST;
}

function transpileLayer2(AST, outfile){
  const {decrypted, decodeConstant} = decryptCodeLayer2(AST);
  const layer2AST = beautifyAndWriteCodeToFile(decrypted, outfile);
  return [layer2AST, decodeConstant];
}

function transpileLayer1(AST, options, outfile){
  const startNodes = options.start ? [options.start] : findPotentialStartNodes(AST);
  write('Start nodes found ' + startNodes);
  const ids = findIdentifiersInNodes(AST, startNodes);

  const functionDeclarations = filterFunctionsFromIds(AST, ids);
  const varAssignmentsNotInFunctions = filterAssignmentsNotInFunctionsFromIds(AST, ids, startNodes[0]); 

  const functionNames = functionDeclarations.map((f) => f.id.name);
  write('functions found: ' + functionNames);

  AST.program.body = varAssignmentsNotInFunctions.concat(functionDeclarations); 
  const codeLayer1 = generate(AST, beautifyOpts).code;
  if(!settings.no_dump) fs.writeFileSync(outfile, codeLayer1);
  write("the code was saved to " + outfile);
}

/**
 * Change the AST so that the calls to the string decoding function are replaced with the decoded strings
 * @param {*} AST 
 * @returns 
 */
function decodeStringsLayer3(AST){
  // this should get us inside the string decrypt function
  const stringBlobAssign = extractBiggestStringAssignment(AST);
  if(stringBlobAssign == undefined) return;
  // decode all the strings
  const stringArray = stringBlobAssign.right.value.split('|');
  let decodedArray = [];
  for (let strId = 0; strId < stringArray.length; strId++) {
    let extractedStr = stringArray[strId];
    for (let i = 0; i <= strId; i++) { 
      extractedStr = extractedStr.substr(1) + extractedStr.substr(0, 1);
    }
    decodedArray[strId] = extractedStr;
  }
  const decodeFunctionName = findStringDecoderFunctionNameLayer3(AST, stringBlobAssign);
  replaceStringDecoderCallsWithStrings(AST, decodedArray, decodeFunctionName);
}

function findStringDecoderFunctionNameLayer3(AST, stringAssignNode){
  let name = 'not found';
  const findStringDecoderFunctionNameVisitor = {
    AssignmentExpression(path) {
      if(path.node === stringAssignNode){
        name = path.parentPath.parentPath.parentPath.node.id.name;
      }
    }
  }

  traverse(AST, findStringDecoderFunctionNameVisitor);
  return name;
}

function replaceStringDecoderCallsWithStrings(AST, decodedArray, decodeFunctionName){
  const findDecodeCallsVisitor = {
    CallExpression(path) {
      if(path.node.callee.name === decodeFunctionName 
        && path.node.arguments.length === 1){
        strId = path.node.arguments[0].value; // obtain argument
        replacementNode = types.stringLiteral(decodedArray[strId]);
        path.replaceWith(replacementNode);
      }
    }
  }

  traverse(AST, findDecodeCallsVisitor);
}

function insertEncryptionNode(AST, encryptedVarNode){
  for (const instr of AST.program.body){
    if(instr.type === "FunctionDeclaration" && instr.body.type === "BlockStatement") {
      instr.body.body.push(encryptedVarNode);
      return;
    }
  }
  // we did not arrive at a block statement inthe program body, so let's try another location
  const findFunctionVisitor = {
    BlockStatement(path) {
      if(path.node.body.length > 20){
        for (const instr of path.node.body){
          if(instr.type == "FunctionDeclaration" && instr.body.type == "BlockStatement") {
            instr.body.body.push(encryptedVarNode);
            path.stop();
          }
        }
        
      }
    }
  }
  traverse(AST,findFunctionVisitor);
}

function filterAssignmentsNotInFunctionsFromIds(AST, ids, startNodeName){
  const assigns = [];
  const findFunctionNodeVisitor = {
    FunctionDeclaration(path) {
      if(path.node.id.name === startNodeName){
        
        for(const statement of path.parentPath.node.body){ // search in main body for assignments
          if(statement.type === "ExpressionStatement" 
          && statement.expression.type === "AssignmentExpression"
          && ids.includes(statement.expression.left.name)
          ){
            assigns.push(statement);
          }
          // search also in if statement blocks for assignments, see 08f06fc48fe8d69e4ab964500150d1b2f5f4279fea2f76fdfcefd32266dfa1af
          if(statement.type === "IfStatement" && statement.consequent.body !== undefined){ 
            for(const ifbodyNode of statement.consequent.body){
              if(ifbodyNode.type === "ExpressionStatement" 
              && ifbodyNode.expression.type === "AssignmentExpression"
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
 * Takes code as text and performs beautification of the code, i.e., string literal concatenation and formatting.
 * Writes the beautified code to the given file.
 * 
 * @param {string} code the code as text
 * @param {string} outfile the output file to write the code to
 * @returns the AST after beautification
 */
function beautifyAndWriteCodeToFile(code, outfile) {
  const ast = parser.parse(code);
  concatStringLiterals(ast);
  const beautifiedCode = generate(ast, beautifyOpts).code;
  if(!settings.no_dump) fs.writeFileSync(outfile, beautifiedCode);
  write("the code was saved to " + outfile);
  return ast;
}

function countInstances(string, word){
  return string.split(word).length - 1;
}

/**
 * decode and return string representation of the decrypted code from layer 3
 * @param {*} layer2AST 
 * @returns the decrypted code wrapped into a function and as a string
 */
function decryptCodeLayer3(layer2AST, decodeConstant){
  const encryptedBlob = extractBiggestStringLiteralValue(layer2AST);
  let decryptedCode = gootloaderDecode(encryptedBlob, decodeConstant);
  decryptedCode = maybeApplyStringReplace(layer2AST, decryptedCode)
  // wrap into function declaration to allow parsing
  return 'function gldr(){ ' + decryptedCode + ' }'; 
}

/**
 * decrypt and return string representation of the decrypted code from layer 2
 * @param {*} layer1AST 
 * @returns decrypted code and extracted decoding constant (for use later)
 */
function decryptCodeLayer2(layer1AST){
  let encryptedVarNode = findLayer1EncryptedCodeBuilder(layer1AST);
  let encryptedBlob = buildEncryptedString(layer1AST, encryptedVarNode);
  if(!encryptedBlob){ 
    // encryptedVarNode was incorrect here, this happens with older gootloader samples where the node 
    // just gets assigned a big string instead of obfuscating it with many string literals that are built up
    encryptedVarNode = extractBiggestStringAssignment(layer1AST);
    encryptedBlob = encryptedVarNode.right.value;
  }
  write('identified encrypted data node: ' + encryptedVarNode.left.name);
  const {key, decodeFunctionName} = extractKeyAndDecodeFunction(layer1AST, encryptedVarNode.left.name);
  write('extracted key: ' + key);
  write('decode function: ' + decodeFunctionName);
  const idxMax = findDecodeConstant(layer1AST, decodeFunctionName);
  write('decode constant found ' + idxMax);
  const decoded = gootloaderDecode(encryptedBlob, idxMax)
  write("decoded " + decoded.length + " bytes");
  const decrypted = gootloaderDecrypt(decoded, key).pop();
  write("decrypted " + decrypted.length + " bytes");
  return {'decrypted' : decrypted, 'decodeConstant': idxMax};
}

/**
 * Based on the name of the decode function, find and extract the decode constant. 
 * This is specific to Gootloader and the way it decodes data.
 * 
 * @param {*} layer1AST 
 * @param {*} decodeFunctionName 
 * @returns 
 */
function findDecodeConstant(layer1AST, decodeFunctionName){
  
  let decodeConstant = 0;

  /**
   * Retrieve the decode constant by checking the right side of the first BinaryExpression with '<' operator
   * This visitor assumes that we are already in the decode function's scope
   */
  const getDecodeConstantVisitor = {
    BinaryExpression(path) {
      if(path.node.operator === "<"){
        decodeConstant = path.node.right.value;
        path.stop();
      }
    }
  }
  /**
   * Determine where the decode function is based on the given decodeFunctionName
   * Once found, traverse only the function's scope for the decode constant
   */
  const findDecodeFunctionVisitor = {
    FunctionDeclaration(path) {
      if(path.node.id.name == decodeFunctionName){
        const { scope, node } = path
        scope.traverse(node, getDecodeConstantVisitor, this);
        path.stop();
      }
    }
  }

  traverse(layer1AST,findDecodeFunctionVisitor);
  return decodeConstant;
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
function extractKeyAndDecodeFunction(AST, encryptVarName){
  let key = '';
  let keyName = '';
  let decodeFunctionName = '';
  const findKeyVarNameVisitor = {
    CallExpression(path) {
      if(path.node.arguments.length === 1 
        && path.node.arguments[0].name === encryptVarName) {
          decodeFunctionName = path.parentPath.node.arguments[0].callee.name;
          keyName = path.parentPath.node.arguments[1].name; // get name of second argument from parent call
          path.stop();
      }
    }
  }

  const findKeyVarContentVisitor = {
    AssignmentExpression(path) {
      if(path.node.left.name === keyName){
        key = path.node.right.value;
        path.stop();
      }
    }
  }

  traverse(AST,findKeyVarNameVisitor);
  traverse(AST,findKeyVarContentVisitor);
  return {key, decodeFunctionName};
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
    if (encryptedStr.substr(idx, keylen) === key) {
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
function gootloaderDecode(encodedStr, idxMax) {

  function flip(somestr, somechar, idx) {
    if (idx % 2) return somestr + somechar;
    else return somechar + somestr;
  }
  let idx = 0;
  let result = "";
  while (idx < idxMax) {
    const charSub = encodedStr.substr(idx,1);
    result = flip(result, charSub, idx);
    idx++;
  }
  return result;
}

/**
 * GootLoader sometimes performs replace operations on the decrypted code
 * Find out if that is the case and do the same
 * 
 * @param {*} layer2AST 
 * @param {*} decryptedCode 
 * @returns 
 */
function maybeApplyStringReplace(AST, decryptedCode){

  let replRex = undefined
  let replTxt = undefined
  
  const findReplacementArgsVisitor = {
    // looking for a very specific pattern here to make sure it is the correct replace call
    // the pattern looks as follows: possible1('?+i?r/a5f ... very long string ...').replace(/\?/g, "'")
    // might loosen it up if necessary
    CallExpression(path){
      const node = path.node;
      if(
        node.arguments.length == 2 && 
        types.isMemberExpression(node.callee) &&
        types.isCallExpression(node.callee.object) &&
        node.callee.object.arguments.length == 1 &&
        types.isStringLiteral(node.callee.object.arguments[0]) &&
        node.callee.object.arguments[0].value.length > 1000 &&
        node.callee.property.name === "replace" &&
        types.isRegExpLiteral(node.arguments[0]) &&
        types.isStringLiteral(node.arguments[1])
      ) {
        const pattern = node.arguments[0].pattern;
        const flags = node.arguments[0].flags;
        replRex =  new RegExp(pattern, flags);
        replTxt = node.arguments[1].value;
        path.stop();
      }
    }
  };

  traverse(AST, findReplacementArgsVisitor);
  
  if(replRex !== undefined && replTxt !== undefined){
    decryptedCode = decryptedCode.replace(replRex, replTxt);
  }

  return decryptedCode;
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
  };
  traverse(AST,findBiggestStringVisitor);
  return str;
}

/**
 * Find largest String in an expression of the form: "a = 'string'" and return the node for the assignment
 * @param {*} AST 
 * @returns assignment expression node that gets assigned the longest string literal
 */
function extractBiggestStringAssignment(AST){
  let maxstrlen = 0;
  let node;
  const findBiggestStringAssignmentVisitor = {
    AssignmentExpression(path) {
      if(path.node.right.type === "StringLiteral"
      && path.node.left.type === "Identifier")
      {
        const str = path.node.right.value;
        if(maxstrlen < str.length) {
          node = path.node;
          maxstrlen = str.length;
        }
      }
    }
  }
  traverse(AST,findBiggestStringAssignmentVisitor);
  return node;
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
  if(encryptedVarNode.right.type === "CallExpression") return encryptedVarNode.right.arguments[0].value;
  // here the encryptedVarNode is assumed to be an AssigmentExpression, 
  // which means the right side of the assignment operation contains the string
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
    if(node.type === "AssignmentExpression") return getIdentifiersFromNode(node.right);
    else if (node.type === "CallExpression" && node.arguments.length > 0) return getIdentifiersFromNode(node.arguments[0]);
    else if(node.type === "Identifier") return [node.name];
    else if(node.type === "BinaryExpression") {
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

  function buildStringAssignMap(assignNodes){
    const arr = assignNodes.filter((n) => n.type === "AssignmentExpression" && n.right.type === "StringLiteral");
    return new Map(arr.map((n) => [n.left.name, n.right.value]));
  }

  // check for each node if it is a string assignment and if so, delete
  function deleteStringAssignmentNodes(nodes){
    const delStringAssignmentsVisitor = {
      AssignmentExpression(path){
        if(path.node.right.type === "StringLiteral" && nodes.includes(path.node)) {
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
  
  function liftAssignments(nodes, maxrecursion = 10){
    if(maxrecursion == 0) return;

    const ids = getIdentifiersFromNodes(nodes);

    if(ids.length == 0) return;
    const assignmentNodes = findAssignmentNodesForNames(AST, ids);

    liftAssignments(assignmentNodes, maxrecursion - 1);
    const strAssignMap = buildStringAssignMap(assignmentNodes);

    deleteStringAssignmentNodes(assignmentNodes);
    replaceIdentifiersWithStringLiterals(strAssignMap);
    concatStringLiterals(AST);
  }

  liftAssignments([encryptedVarNode]);
}

function findAssignmentNodesForNames(AST, namesList){
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

/**
 * Concatenate string literals in the whole AST
 * if the input is "a" + "b" + "c"
 * the output will be "abc"
 * 
 * @param {object} AST the abstract syntax tree
 */
function concatStringLiterals(AST){
  traverse(AST, { 
        BinaryExpression: {
        exit: (path) => {
          if(path.node.left.type === "StringLiteral" && path.node.right.type === "StringLiteral"){
            const resval = path.node.left.value + path.node.right.value;
            path.replaceWith(types.stringLiteral(resval));
          } 
        }
      }
    }
  );
}

/**
 * Find the node that holds the encrypted string of the 4th code layer
 * 
 * @param {object} AST the abstract syntax tree
 * @returns node that gets assigned the encrypted string for the next layer
 */
function findLayer4EncryptedCodeBuilder(AST) {
  let matchingNode = 'not found';
  let maxCount = -1;

  function countBinaryExpressionChainWithIdentifiers(node){
    if(node.left.type === "BinaryExpression"
    && node.right.type === "Identifier") {
      return 1 + countBinaryExpressionChainWithIdentifiers(node.left);
    } else return 0;
  }

  let findEncryptedCodeBuilderVisitor = {
    AssignmentExpression(path) {
      if(path.node.right.type === "CallExpression" 
      && path.node.right.arguments.length == 1 
      && path.node.right.arguments[0].type === "BinaryExpression" 
      ) {
        let cnt = countBinaryExpressionChainWithIdentifiers(path.node.right.arguments[0]);
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
 * Find the node that holds the encrypted string of the first code layer
 * 
 * @param {object} AST the abstract syntax tree
 * @returns node that gets assigned the encrypted string for the next layer
 */
function findLayer1EncryptedCodeBuilder(AST) {
  let matchingNode = 'not found';
  let maxCount = -1;

  function countBinaryExpressionChainWithIdentifiers(node){
    if(node.left.type === "BinaryExpression"
    && node.right.type === "Identifier") {
      return 1 + countBinaryExpressionChainWithIdentifiers(node.left);
    } else return 0;
  }

  let findEncryptedCodeBuilderVisitor = {
    AssignmentExpression(path) {
      if(path.node.right.type === "BinaryExpression" 
      && path.node.right.right.type === "Identifier" ) {
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
        path.node.arguments.length == 1                     // exactly one argument
        && path.node.arguments[0].type === 'NumericLiteral'  // argument is a numeric literal
        && typeof path.node.callee.name !== 'undefined'     // function has a name
        ) {
          let name = path.node.callee.name;
          if(!matchingNodes.includes(name)
          && name.length <= 10
          && !name.includes('_')) {
          matchingNodes.push(name);
        }
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
    write('parser will try to find the starting point, to set another one, use the option -n')
  }
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
      if(typeof foundNodes == 'undefined' || foundNodes.length === 0) continue;
      identifiers = identifiers.concat(foundNodes);
      ignoreList.push(currNode);
    } 
  }
  if (identifiers.length === 0) return [];
  if (maxdepth === 0) {
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
      if(path.node.id.name === nodeName){
        const { scope, node } = path
        scope.traverse(node, collectIdentifiersVisitor, this);
        path.stop();
      }
    },
  }
  const assignFinderVisitor = {
  AssignmentExpression(path){
      if(path.node.left.name === nodeName){
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
