using System;
using System.Reflection;
using HarmonyLib;
using AsmResolver.DotNet;
using System.Linq;
using AsmResolver.PE.DotNet.Cil;
using System.Collections.Generic;
using AsmResolver.DotNet.Serialized;
using System.IO;

/**
 * Browser Fixer string decrypter
 * probably a ConfuserEx2 string encryption variant
 * script is based on Dump_GUY's ConfuserEx2_String_Decryptor, see github.com/Dump-GUY/ConfuserEx2_String_Decryptor
 * test sample: 9d59ab9bd34c3146c086feb0605048005433d4e9aba32516c07dbd02dd48b240 BrowserFixerSetup
 * test sample: 6981b024f5614d6a9e9f154d4e985b728dd09dcf2c716c2219235df61ed97acc BuyBricksAiSetup
 * 
 * key characteristcs of sample's decryption function:
 *      one static non-generic string decryption function that takes an integer as input
 *      MBA in string decryption
 *      decrypt function returns 'X0X' if it detects reflection usage
 *      reflection usage detection: checks types of methods in the stackframe and checks the assembly that called the function
 * 
 * BF String Decrypter:
 *      dynamically executes the decrypt function - NOT SAFE TO USE OUTSIDE OF VM
 *      defeats reflection usage detection via Harmony2 hooks
 *      patches IL instructions that call the decrypt function with the decrypted string
 *      saves a cleaned version of the assembly to <filename>-cleaned
 */

namespace BF_String_Decrypter
{
    internal class Program
    {
        static Assembly LoadedAssembly;

        static void Main(string[] args)
        {
            Console.Title = "Dynamic BF String Decryptor";
            if (args.Length == 0)
            {
                Console.WriteLine("Use BF_String_Decryptor.exe (32-bit) on 32-bit samples and BF_String_Decryptor.exe (64-bit) on 64-bit samples");
                Console.WriteLine("Usage: Drag&Drop or BF_String_Decryptor.exe <filepath>");
                Console.ReadKey();
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine($"File not found: {args[0]}");
            }
            string path = Path.GetFullPath(args[0]);
            Console.WriteLine("Path: " + path);
            ModuleDefinition moduleDef = ModuleDefinition.FromFile(path);
            var strDecMethods = FindStrDecryptMethods(moduleDef);
            if (!strDecMethods.Any())
            {
                Console.WriteLine("String decryption methods not found!");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("Loading assembly");
            LoadedAssembly = Assembly.LoadFrom(path);
            var modules = LoadedAssembly.GetModules();
            InstallHooks();

            foreach (var module in modules)
            {
                foreach (var strDecMethod in strDecMethods)
                {   
                    DecryptStringsforDecryptFunction(module, moduleDef, strDecMethod);
                }
            }
            string outpath = path + "-cleaned";
            if (path.EndsWith(".exe") || path.EndsWith(".dll"))
            {
                outpath = path.Insert(path.Length - 4, "-cleaned");
                
            }
            moduleDef.Write(outpath);
            Console.WriteLine("File written to " + outpath);
            Console.WriteLine("Finished! Press any key to exit.");
            Console.ReadKey();
        }

        private static void DecryptStringsforDecryptFunction(Module module, ModuleDefinition moduleDef, MethodDefinition strDecMethod)
        {
            var token = strDecMethod.MetadataToken.ToInt32();
            var strDecMethodRefl = module.ResolveMethod(token);
            Console.WriteLine($"Using decrypt function 0x{token:X} " + strDecMethodRefl);
            foreach (TypeDefinition type in moduleDef.GetAllTypes().Where(t => t.Methods.Count > 0))
            {
                foreach (MethodDefinition method in type.Methods.Where(m => m.CilMethodBody != null))
                {
                    DecryptStringsInMethod(strDecMethod, strDecMethodRefl, method);
                }
            }
        }

        private static void DecryptStringsInMethod(MethodDefinition strDecMethod, MethodBase strDecMethodRefl, MethodDefinition method)
        {
            foreach (var inst in method.CilMethodBody.Instructions.Where(i => i.OpCode == CilOpCodes.Call && i.Operand is SerializedMethodDefinition))
            {
                if (((SerializedMethodDefinition)inst.Operand).MetadataToken.ToInt32() == strDecMethod.MetadataToken.ToInt32())
                {

                    var index = method.CilMethodBody.Instructions.IndexOf(inst);
                    for (int i = index - 1; i > index - 4; i--)
                    {
                        if (method.CilMethodBody.Instructions[i].OpCode == CilOpCodes.Ldc_I4)
                        {

                            var encValue = (int)method.CilMethodBody.Instructions[i].Operand;
                            try
                            {
                                string decString = (string)((MethodInfo)strDecMethodRefl).Invoke(null, new object[] { encValue });
                                Console.WriteLine("Decrypted: " + decString);
                                inst.ReplaceWithNop();
                                method.CilMethodBody.Instructions[i].ReplaceWith(CilOpCodes.Ldstr, decString);

                            }
                            catch (TargetInvocationException ex)
                            {
                                if (ex.ToString().Contains("EndOfStreamException"))
                                {
                                    Console.WriteLine("End Of Stream - X0X");
                                }
                                else
                                {
                                    Console.WriteLine(ex);
                                }
                            }
                            break;

                        }
                    }

                }
            }
        }

        private static List<MethodDefinition> FindStrDecryptMethods(ModuleDefinition moduleDef)
        {
            List<MethodDefinition> strDecMethods = new List<MethodDefinition>();
            foreach (TypeDefinition type in moduleDef.GetAllTypes().Where(t => t.Methods.Count > 0))
            {
                foreach (MethodDefinition method in type.Methods.Where(m => m.CilMethodBody != null && m.Parameters.Count == 1 && m.Parameters[0].ParameterType.FullName.Equals("System.Int32")))
                {
                    if (method.CilMethodBody.Instructions.Any(inst => inst.ToString().Contains("TryGetValue")))
                    {
                        strDecMethods.Add(method);
                    }
                }
            }
            return strDecMethods;
        }

        private static void InstallHooks()
        {
            InstallHook("System.Reflection.Assembly:GetCallingAssembly", "PreFix_GetCallingAssembly");
            InstallHook("System.Diagnostics.StackTrace:GetFrame", "PreFix_GetFrame");
        }

        private static void InstallHook(string methodName, string hookName)
        {
            var target = AccessTools.Method(methodName);
            if (target == null)
                throw new Exception("Could not resolve " + methodName);

            var harmony = new Harmony(methodName);
            var stub = typeof(Program).GetMethod(hookName);
            harmony.Patch(target, new HarmonyMethod(stub));
            Console.WriteLine("hook installed for " + methodName);
        }

        public static bool PreFix_GetCallingAssembly(ref Assembly __result)
        {
            __result = LoadedAssembly; // sets the result --> return value of original called method
            Console.WriteLine("GetCallingAssembly hook was called, I returned " + __result);
            return false; // skip executing original GetCallingAssembly() method
        }

        public static bool PreFix_GetFrame(ref int index)
        {
            int prev_index = index;
            index = 4;
            Console.WriteLine("GetFrame hook was called with index "+prev_index+", I set the stack frame index to " + index);
            return true; // we execute the orginal function and just modify the argument
        }

    }
}
