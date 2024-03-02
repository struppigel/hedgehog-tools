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
    .usage('node.exe rename_identifiers.js -f <sample>')
    .option('-f, --file <value>', 'The file to deobfuscate')
    .parse(process.argv);

  const options = commander.opts();
  printHints(options);
  if(!options.file) return;
  const infile = options.file;

  const script = fs.readFileSync(infile, 'utf-8');
  const AST = parser.parse(script, {});
  const outfile = infile + ".renamed";
  console.log("start renaming");
  renameIdentifiers(AST, options);

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
  }

function renameIdentifiers(AST) {
    const rename_prefix = 'ren_';
    var name_counter = 0;
    
    const identifierRenameVisitor = {
      Identifier(path){
        const name = path.node.name;
        if(!name.startsWith(rename_prefix)) {
            path.scope.rename(name, rename_prefix + name_counter++);
        }
      }
    }      
    traverse(AST, identifierRenameVisitor);
 }
