# from https://www.reddit.com/r/ReverseEngineering/comments/l0khbw/auditing_system_calls_for_command_injection/
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.util.task import ConsoleTaskMonitor

sources = [
    'sprintf',
    'snprintf',
    'memcpy',
    'strcpy'
]

sinks = [
    'system',
]


def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    res = ifc.decompileFunction(func, 60, monitor)
    return res.getHighFunction()


def get_stack_va_from_varnode(func, varnode):
    if type(varnode) not in [Varnode, VarnodeAST]:
        raise Exception("Invalid value passed to get_associated_stack_variable()")
    local_variables = func.getAllVariables()
    vndef = varnode.getDef()
    if vndef:
        vndef_inputs = vndef.getInputs()
        for defop_input in vndef_inputs:
            defop_input_offset = defop_input.getAddress().getOffset()
            for lv in local_variables:
                unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset()
                if unsigned_lv_offset == defop_input_offset:
                    return lv
        # if we get here, varnode is likely a "acstack##" variable
        # We'll need a LocalSymbolMpa from a HighFunction to continue analysis
        hf = get_high_function(func)
        lsm = hf.getLocalSymbolMap()
        for vndef_input in vndef_inputs:
            defop_input_offset = vndef_input.getAddress().getOffset()
            for symbol in lsm.getSymbols():
                if symbol.isParameter():
                    # don't process parameters in the localSymbol map
                    continue
                if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset():
                    return symbol
    return None


def main():
    fm = currentProgram.getFunctionManager()
    functions = [func for func in fm.getFunctions(True)]
    #######
    ##Step 1
    ##
    ########
    function_names = [func.name for func in functions]
    if (set(source) & set(function_names)) and (set(sinks) & set(function_names)):
        print("This target contains interesting things")
    else:
        print("This target not contians interestring things")
        return

    ##############
    ##Step 2
    ##
    #####################
    interestring_functions = []
    for func in functions:
        monitor = ConsoleTaskMonitor()
        called_functions = func.getCalledFunctions(monitor)
        called_functions_names = [cf.name for cf in called_functions]
        source_callers = set(called_functions_names) & set(sources)
        sink_callers = set(called_functions_names) & set(sinks)
        if source_callers and sink_callers:
            interestring_functions.append(func)
    if len(interestring_functions) <= 0:
        print("\nNo interestring function found to analyze. Done")
        return
    else:
        print("\nFound {} interestring function to analyze:".format(len(interestring_functions)))
        for func in interestring_functions:
            print("  {}".fromat(func.name))
    ########
    ##Step 3
    ##
    ############
    for func in interestring_functions:
        print('\nAnalyzing function: {}'.format(func.name))
        source_args = []
        sink_args = []
        hf = get_high_function()
        opiter = hf.getPcodeOps()
        while opiter.hasNext():
            op = opiter.next()
            mnemonic = op.getMnemonic()
            if mnemonic == 'CALL':
                opinputs = op.getInputs()
                call_target = opinputs[0]
                call_target_addr = call_target.getAddress()
                call_target_name = fm.getFunctionAt(call_target_addr).getName()
                if call_target_name == 'system':
                    arg = opinputs[1]  # VarnodeAST
                    sv = get_stack_va_from_varnode(func, arg)
                    if sv:
                        # sv is a LocalVariableDB
                        addr = op.getSeqnum().getTarget()
                        sink_args.append(sv.getName())
                        print("  >> {}: system({})".format(addr, sv.getName()))
                elif call_target_name == 'sprintf':
                    arg = opinputs[1]  # VarnodeAST
                    sv = get_stack_va_from_varnode()
                    if sv:
                        addr = op.getSeqnum().getTarget()
                        source_args.append(sv.getName())
                        print(" >> {} : sprintf({}, ...)".format(addr, sv.getName()))
                elif call_target_name == 'snprintf':
                    arg = opinputs[1]  # VarnodeAST
                    sv = get_stack_va_from_varnode()
                    if sv:
                        addr = op.getSeqnum().getTarget()
                        source_args.append(sv.getName())
                        print(" >> {} : snprintf({}, ...)".format(addr, sv.getName()))
        if len(set(sink_args) & set(source_args)) > 0:
            print("  [!]Alert: Function {} appears to contains a vulnerable `system` call pattern")


if __name__ == "__main__":
    main()
