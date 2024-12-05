import re
from graphviz import Digraph
# Define instruction patterns including new branch conditions
instructions = {
    'MOV': r'MOV\s+(R\d+),\s*(#?\d+|R\d+)',  # Allow immediate values with # prefix
    'ADD': r'ADD\s+(R\d+),\s*(R\d+),\s*(#?\d+|R\d+)',
    'SUB': r'SUB\s+(R\d+),\s*(R\d+),\s*(#?\d+|R\d+)',
    'MUL': r'MUL\s+(R\d+),\s*(R\d+),\s*(#?\d+|R\d+)',
    'AND': r'AND\s+(R\d+),\s*(R\d+),\s*(#?\d+|R\d+)',
    'ORR': r'ORR\s+(R\d+),\s*(R\d+),\s*(#?\d+|R\d+)',
    'EOR': r'EOR\s+(R\d+),\s*(R\d+),\s*(#?\d+|R\d+)',
    'B': r'B\s+(\w+)',
    'BEQ': r'BEQ\s+(\w+)',
    'BNE': r'BNE\s+(\w+)',
    'BGT': r'BGT\s+(\w+)',
    'BLT': r'BLT\s+(\w+)',
    'BGE': r'BGE\s+(\w+)',
    'BLE': r'BLE\s+(\w+)',
    'CMP': r'CMP\s+(R\d+),\s*(#?\d+|R\d+)'  # Compare and update condition flags
}

def display_ast(ast):
    print("Abstract Syntax Tree:")
    for node in ast:
        instr, operands, label_address = node
        if label_address is not None:
            print(f"{instr} {operands} -> Jump to address {label_address}")
        else:
            print(f"{instr} {operands}")

# You would call this in your main function after parsing the tokens:



def lexer(code):
    tokens = []
    lines = code.strip().split('\n')
    labels = {}
    address = 0
    for line_index, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('//'):  # Skip empty lines or comments
            continue
        label_match = re.match(r'(\w+):', line)
        if label_match:
            labels[label_match.group(1)] = address
            continue  # Labels do not generate tokens but mark positions for jumps
        matched = False
        for instr, pattern in instructions.items():
            match = re.match(pattern, line)
            if match:
                tokens.append((instr, match.groups()))
                address += 1
                matched = True
                break
        if not matched:  # If no pattern matches, report a syntax error
            return None, None, f"Syntax error on line {line_index + 1}: {line}"
    return tokens, labels, None



def parser(tokens, labels):
    ast = []
    regs = {f'R{i}': None for i in range(16)}
    for instr, operands in tokens:
        label_address = labels.get(operands[0]) if instr in ['B', 'BEQ', 'BNE', 'BGT', 'BLT', 'BGE', 'BLE'] else None
        ast.append((instr, operands, label_address))
    return ast, regs
def execute_alu(instr, operands, regs):
    reg = operands[0]
    if instr == 'MOV':
        value = int(operands[1][1:]) if operands[1].startswith('#') else regs[operands[1]]
        regs[reg] = value
    else:
        src1, src2 = operands[1], operands[2]
        val1 = regs[src1] if src1 in regs else None
        val2 = int(src2[1:]) if src2.startswith('#') else regs[src2]

        if val1 is None or val2 is None:
            raise ValueError(f"Attempted to use uninitialized register: {src1 if val1 is None else src2}")

        if instr == 'ADD':
            regs[reg] = val1 + val2
        elif instr == 'SUB':
            regs[reg] = val1 - val2
        elif instr == 'MUL':
            regs[reg] = val1 * val2
        elif instr == 'AND':
            regs[reg] = val1 & val2
        elif instr == 'ORR':
            regs[reg] = val1 | val2
        elif instr == 'EOR':
            regs[reg] = val1 ^ val2
    print(f"Executed {instr} on {reg}, result: {regs[reg]}")




def execute_cmp(instr, operands, regs):
    reg = operands[0]
    src = int(operands[1][1:]) if operands[1].startswith('#') else regs[operands[1]]
    comparison = regs[reg] - src
    regs['Z'] = (comparison == 0)
    regs['N'] = (comparison < 0)  # Negative if the result is negative


def execute_branch(instr, operands, regs, label_address, current_pc):
    should_jump = False
    if instr == 'B':
        should_jump = True
    elif instr == 'BEQ' and regs.get('Z', False):
        should_jump = True
    elif instr == 'BNE' and not regs.get('Z', False):
        should_jump = True
    elif instr == 'BGT' and not regs.get('N', False) and not regs.get('Z', False):
        should_jump = True
    elif instr == 'BLT' and regs.get('N', False):
        should_jump = True
    elif instr == 'BGE' and (not regs.get('N', True) or regs.get('Z', False)):
        should_jump = True
    elif instr == 'BLE' and (regs.get('N', True) or regs.get('Z', False)):
        should_jump = True

    if should_jump:
        return label_address
    else:
        return None



def execute(ast, regs):
    pc = 0
    while pc < len(ast):
        instr, operands, label_address = ast[pc]
        
        if instr in ['MOV', 'ADD', 'SUB', 'MUL', 'AND', 'ORR', 'EOR']:
            execute_alu(instr, operands, regs)
            pc += 1
        elif instr == 'CMP':
            execute_cmp(instr, operands, regs)
            pc += 1
        elif instr in ['B', 'BEQ', 'BNE', 'BGT', 'BLT', 'BGE', 'BLE']:
            new_pc = execute_branch(instr, operands, regs, label_address, pc)
            if new_pc is not None:
                pc = new_pc
            else:
                pc += 1
        else:
            pc += 1
    return regs


from prettytable import PrettyTable

def display_registers(regs):
    table = PrettyTable()
    table.field_names = ["Register", "Value"]
    for reg, value in regs.items():
        table.add_row([reg, value])
    print(table)

from graphviz import Digraph
import os
from graphviz import Digraph

def visualize_ast_detailed(ast):
    dot = Digraph(comment='The Abstract Syntax Tree', format='png')
    dot.attr(rankdir='TB', size='10', dpi='500')  # Increase DPI for higher resolution
    dot.attr('node', shape='box', style='filled', color='lightgrey')
    dot.attr('edge', arrowsize='0.6')
    for i, (instr, operands, label_address) in enumerate(ast):
        with dot.subgraph(name=f'cluster_{i}') as c:
            c.attr(style='filled', color='lightgrey')
            c.node_attr.update(style='filled', color='white')
            node_label = f"{instr}"
            c.node(f"instr_{i}", label=node_label)

            for j, operand in enumerate(operands):
                c.node(f"op_{i}_{j}", label=operand)
                c.edge(f"instr_{i}", f"op_{i}_{j}", constraint='false')

            if label_address is not None:
                c.attr(label=f'Jump to {label_address}')
                dot.edge(f"instr_{i}", str(label_address), label="Branch", style="dashed")
            else:
                c.attr(label=f'Instruction {i}')
    
    # Output directory check
    output_directory = 'output'
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    dot.render(filename=os.path.join(output_directory, 'detailed_ast_graph'), view=True)



def main(filename):
    with open(filename, 'r') as file:
        code = file.read()

    tokens, labels, error = lexer(code)
    if error:
        print(error)  # Display the error message and exit
        return error

    ast, regs = parser(tokens, labels)
    if not ast:  # If AST is empty, handle it (possibly another error check here)
        return "Error parsing tokens"

    result = execute(ast, regs)
    display_registers(result)
    visualize_ast_detailed(ast)  # Assuming visualization doesn't affect execution

    return "Execution completed."

if __name__ == "__main__":
    filename = 'input.txt'
    output = main(filename)
    print(output)