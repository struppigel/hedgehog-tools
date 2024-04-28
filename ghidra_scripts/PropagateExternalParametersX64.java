/* ###
 * This script is a modification of 
 * https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/PropagateExternalParametersScript.java 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// This script propagates Windows external and library function parameter names and types
// It puts the parameter names and types in the comments next to the pushes before a function call.
// It is the x64 variant of the PropagateExternalParameters.java script / analysis
// It currently does not check for branches in the middle of a series of parameters
//@category Analysis
//@author Original code: GHIDRA, modification: Karsten Hahn

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.Register;
import java.util.Arrays;

public class PropagateExternalParametersX64 extends GhidraScript {
	private List<PushedParamInfo> results = new ArrayList<>();

	@Override
	public void run() throws Exception {
		println("propagate params started");
		Listing listing = currentProgram.getListing();
		FunctionManager functionManager = currentProgram.getFunctionManager();

		ReferenceManager refMan = currentProgram.getReferenceManager();

		// iterate over all external symbols
		SymbolTable symTab = currentProgram.getSymbolTable();
		SymbolIterator externalSymbols = symTab.getExternalSymbols();
		while (externalSymbols.hasNext()) {
			Symbol extSym = externalSymbols.next();
			if (extSym.getSymbolType() == SymbolType.FUNCTION) {
				Function extFunc = functionManager.getFunctionAt(extSym.getAddress());
				println("found " + extFunc);
				Parameter[] params = extFunc.getParameters();
				println("params " + Arrays.toString(params));
				if (params.length == 0) {
					continue;
				}
				Reference[] references = extSym.getReferences();
				processExternalFunction(listing, refMan, references, extFunc, params,
					extSym.getName());
			}
		}

		// use the 'results' to propagate param info to the local variables, data, and params of
		// the calling function
		for (int i = 0; i < results.size(); i++) {
			PushedParamInfo ppi = results.get(i);
			Instruction instr = listing.getInstructionAt(ppi.getAddress());
			int opType = instr.getOperandType(0);

			if (!instr.getOperandRefType(0).isData()) {
				continue;
			}

			//If operand of pushed parameter points to data make a symbol and comment at that location
			if (((opType & OperandType.ADDRESS) != 0) && (((opType & OperandType.DATA) != 0)) ||
				((opType & OperandType.SCALAR) != 0) || ((opType & OperandType.DYNAMIC) != 0)) {
				Reference[] refs = listing.getCodeUnitAt(ppi.getAddress()).getOperandReferences(0);

				if ((refs.length > 0) && (refs[0].isMemoryReference())) {
					Address dataAddress = refs[0].getToAddress();

					DataType dt = null;
					dt = ppi.getDataType();
					Data data = getDataAt(dataAddress);
					boolean isString = false;
					if ((data != null) && data.hasStringValue()) {
						isString = true;
					}

					String symbolName = new String(ppi.getName() + "_" + dataAddress.toString());
					String newComment = new String(
						ppi.getName() + " parameter of " + ppi.getCalledFunctionName() + "\n");

					List<Symbol> symbols = getSymbols(symbolName, null);

					if (symbols.isEmpty() && !isString) {
						createLabel(dataAddress, symbolName, true, SourceType.USER_DEFINED);
					}

					String currentComment = getPlateComment(dataAddress);
					if (currentComment == null) {
						setPlateComment(dataAddress, newComment);
					}
					else if (!currentComment.contains(ppi.getCalledFunctionName())) {
						setPlateComment(dataAddress, currentComment + newComment);
					}

					if ((data != null) &&
						(listing.getCodeUnitAt(dataAddress)
								.getMnemonicString()
								.startsWith(
									"undefined"))) {
						clearListing(dataAddress);
					}
					if (listing.isUndefined(dataAddress, dataAddress.add(dt.getLength() - 1))) {
						try {
							createData(dataAddress, dt);
							printf("Data Created at %s : %s ( %s )\n", dataAddress.toString(),
								newComment.replace("\n", ""), ppi.getAddress().toString());
						}
						catch (Exception e) {
							printf("Error making data: %s", e.toString());
						}
					}

				}

			}

		}

	} // end of run

	private void processExternalFunction(Listing listing, ReferenceManager refMan,
			Reference[] extRefs, Function extFunc, Parameter[] params, String extFuncName) {

		for (Reference extRef : extRefs) {

			Address refAddr = extRef.getFromAddress();

			String refMnemonic = listing.getCodeUnitAt(refAddr).getMnemonicString();
			Function calledFromFunc = listing.getFunctionContaining(refAddr);
			if (calledFromFunc == null) {
				continue;
			}

			if ((refMnemonic.equals(new String("JMP")) && (calledFromFunc.isThunk()))) {
				//println(calledFromFunc.getName() + " is a thunk. Refs are:");
				ReferenceIterator tempIter = refMan.getReferencesTo(calledFromFunc.getEntryPoint());
				while (tempIter.hasNext()) {
					Reference thunkRef = tempIter.next();
					Address thunkRefAddr = thunkRef.getFromAddress();
					String thunkRefMnemonic =
						listing.getCodeUnitAt(thunkRefAddr).getMnemonicString();
					Function thunkRefFunc = listing.getFunctionContaining(thunkRefAddr);
					if ((thunkRefMnemonic.equals(new String("CALL")) && (thunkRefFunc != null))) {
						CodeUnitIterator codeUnitsToRef = getCodeUnitsFromLastCallToRef(thunkRefFunc, thunkRefAddr);
						propagateRegisterParams(params, codeUnitsToRef, extFunc.getName());
						codeUnitsToRef = getCodeUnitsFromFunctionStartToRef(calledFromFunc, refAddr);
						propogateStackParams(params, codeUnitsToRef, extFunc.getName());
						println("Processing external function: " + extFuncName + " at " + thunkRefAddr.toString());
					}
				}
			}
			else if ((refMnemonic.equals(new String("CALL")))) {// not a thunk
				CodeUnitIterator codeUnitsToRef = getCodeUnitsFromLastCallToRef(calledFromFunc, refAddr);
				propagateRegisterParams(params, codeUnitsToRef, extFunc.getName());
				codeUnitsToRef = getCodeUnitsFromFunctionStartToRef(calledFromFunc, refAddr);
				propogateStackParams(params, codeUnitsToRef, extFunc.getName());
				println("Processing external function: " + extFuncName + " at " + refAddr.toString());
			}
		}//end of extRef loop
	}

	/*
	 * Function to skip the parameters of a call that is in the middle of the parameters I am
	 * trying to populate. For example:
	 * PUSH arg 4 to call func1           ; put arg 4 of func1 here
	 * PUSH arg 3 to call func1           ; put arg 3 of func1 here
	 * PUSH arg 3 to call func2 ---|
	 * PUSH arg 2 to call func2    |
	 * PUSH arg 1 to call func2	   | -- want to bypass these
	 * CALL func2               ___|
	 * PUSH arg 2 to call func1           ; put arg2 of func1 here
	 * PUSH arg 1 to call func1           ; put arg1 of func1 here
	 * CALL func1
	 */

	// get the number of pushes for a code unit if it is a call
	int numParams(CodeUnit cu) {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Reference[] opref = cu.getReferencesFrom();

		Address toAddr = null;
		Function f = null;
		int numParams = 0;
		if (opref.length != 0) {
			toAddr = opref[0].getToAddress();

			f = functionManager.getReferencedFunction(toAddr);
			if (f != null) {
				//println("Call in middle at " + cu.getMinAddress().toString() + " " + f.getName());
				Parameter[] prms = f.getParameters();
				numParams = prms.length;

			}
		}
		return numParams;
	}

	CodeUnitIterator getCodeUnitsFromFunctionStartToRef(Function func, Address refAddr) {
		if (func == null) {
			return null;
		}

		Listing listing = currentProgram.getListing();
		AddressSetView funcAddresses = func.getBody();
		CodeUnit referenceCodeUnit = listing.getCodeUnitAt(refAddr);
		Address referenceMinAddress = referenceCodeUnit.getMinAddress();

		CodeUnit previousCodeUnit = listing.getCodeUnitBefore(referenceMinAddress);
		Address previousMinAddress = previousCodeUnit.getMinAddress();
		AddressIterator it = funcAddresses.getAddresses(previousMinAddress, false);
		AddressSet addrSet = new AddressSet();
		while (it.hasNext()) {
			Address addr = it.next();
			addrSet.addRange(addr, addr);
		}
		return listing.getCodeUnits(addrSet, false);
	}
	
	CodeUnitIterator getCodeUnitsFromLastCallToRef(Function func, Address refAddr) {
		if (func == null) {
			return null;
		}
		boolean foundCall = false;
		Listing listing = currentProgram.getListing();
		AddressSetView funcAddresses = func.getBody();
		CodeUnit referenceCodeUnit = listing.getCodeUnitAt(refAddr);
		Address referenceMinAddress = referenceCodeUnit.getMinAddress();
		CodeUnit previousCodeUnit = listing.getCodeUnitBefore(referenceMinAddress);
		referenceMinAddress = previousCodeUnit.getMinAddress();
		
		InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
		while(instrIter.hasNext()){
			Instruction inst = instrIter.next();
			if(inst.getMinAddress().equals(refAddr)){
				break;
			}
			if(inst.getMnemonicString().equals("CALL")){
				referenceMinAddress = inst.getMinAddress();
				foundCall = true;
			}
		}
		
		AddressIterator it = funcAddresses.getAddresses(referenceMinAddress, foundCall);
		AddressSet addrSet = new AddressSet();
		while (it.hasNext()) {
			Address addr = it.next();
			addrSet.addRange(addr, addr);
		}
		return listing.getCodeUnits(addrSet, true);
	}

	/* this function currently makes assumptions that worked well for the shellcode
	* I applied it to but won't work every time. Might be better to use the backward slice.
	*/
	void propagateRegisterParams(Parameter[] params, CodeUnitIterator cuIt, String extFuncName) {
		println("checking: " + extFuncName);
		int index = 0;
		int numRegistersUsed = params.length;
		if (numRegistersUsed > 4) numRegistersUsed = 4;

		while (cuIt.hasNext() && (index < params.length)) {
			CodeUnit cu = cuIt.next();
			// param passed by register
			if (index < 4 && numRegistersUsed > index){
				// ignore the pushes, these are not the right ones
				if (cu.getMnemonicString() != null && cu.getMnemonicString().equals("PUSH")) {
					continue;
				}
				// check every register
				for(int i = 0; i < 4; i++) {
					Register reg = getRegisterForIndex(i);
					if(isMatchingRegister(cu, reg)){
						println("matching register found for index " + i + " for funcname " + extFuncName + " at " + cu.getMinAddress());
						setEOLComment(cu.getMinAddress(), params[i].getDataType().getDisplayName() +
							" " + params[i].getName() + " for " + extFuncName);
						addResult(params[i].getName(), params[i].getDataType(),
							cu.getMinAddress(), extFuncName);
						index++;
					}
				}
			}
		}
	}
	
	void propogateStackParams(Parameter[] params, CodeUnitIterator cuIt, String extFuncName) {

		int index = 4;
		int numSkips = 0;
		boolean hasBranch = false;

		while (cuIt.hasNext() && (index < params.length) && !hasBranch) {
			CodeUnit cu = cuIt.next();

			// need to take into account calls between the pushes and skip the pushes for those calls
			// skip pushes that are used for another call

			// if label, then probably a branch, allow current push to be commented and
			// next time through stop
			// can also be a branch if not label there but this case should still have parameters set
			// before it as long as not an unconditional jump - this wouldn't make sense so it shouldn't happen

			if (cu.getLabel() != null) {
				hasBranch = true;
			}

			if (cu.getMnemonicString().equals(new String("CALL"))) {
				numSkips += numParams(cu);
				//printf("numSkips = %d", numSkips);
			}
			else if (cu.getMnemonicString().equals(new String("PUSH"))) {
				if (numSkips > 0) {
					numSkips--;
				}
				else {
					setEOLComment(cu.getMinAddress(), params[index].getDataType().getDisplayName() +
						" " + params[index].getName() + " for " + extFuncName);
					// add the following to the EOL comment to see the value of the optype
					//	+" " + toHexString(currentProgram.getListing().getInstructionAt(cu.getMinAddress()).getOperandType(0), false, true)
					addResult(params[index].getName(), params[index].getDataType(),
						cu.getMinAddress(), extFuncName);
					index++;
				}
			}

		}
	}
	
	private boolean isMatchingRegister(CodeUnit cu, Register reg){
		if(reg == null) return false;
		if(cu instanceof Instruction){
			Instruction inst = (Instruction) cu;
			for ( int opIdx = 0; opIdx < inst.getNumOperands(); opIdx++ ) {
				Register register = inst.getRegister(opIdx);
				if (reg.equals(register)) {
					return true;
				}
			}
		}
		return false;
	}
	
	private Register getRegisterForIndex(int index){
		ProgramContext context = currentProgram.getProgramContext();
		switch(index){
			case 0: return context.getRegister("RCX");
			case 1: return context.getRegister("RDX");
			case 2: return context.getRegister("R8");
			case 3: return context.getRegister("R9");
			default: return null;
		}
	}

	// for now all calledFuncNames are extFuncNames
	void addResult(String name, DataType dataType, Address addr, String calledFuncName) {
		PushedParamInfo param = new PushedParamInfo(name, dataType, addr, calledFuncName);
		results.add(param);
	}

	// info about the pushed parameter that gets applied to the calling functions params and locals and referenced data
	private class PushedParamInfo {
		private String name;
		private DataType dataType;
		private Address addr;
		private String calledFunctionName;

		PushedParamInfo(String name, DataType dataType, Address addr, String calledFunctionName) {
			this.name = name;
			this.dataType = dataType;
			this.addr = addr;
			this.calledFunctionName = calledFunctionName;
		}

		String getName() {
			return name;
		}

		DataType getDataType() {
			return dataType;
		}

		Address getAddress() {
			return addr;
		}

		String getCalledFunctionName() {
			return calledFunctionName;
		}
	}
}
