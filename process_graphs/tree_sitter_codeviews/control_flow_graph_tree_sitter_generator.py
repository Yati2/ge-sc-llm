import networkx as nx

from .tree_parser.parser_driver import ParserDriver
from .codeviews.CFG.CFG_driver import CFGDriver



def tree_sitter_generate_cfg(source_code, ori_name='contract_0.sol', src_language='solidity', CFG_output=None):
    parser = ParserDriver(src_language, source_code)
    cleaned_src_code = parser.src_code
    cfg_driver = CFGDriver(src_language, cleaned_src_code, CFG_output)
    cfg_graph = cfg_driver.graph
    nx.set_node_attributes(cfg_graph, ori_name, 'source_file')
    source_lines = {}
    node_info = {}
    node_to_remove = []
    for n_id, node in cfg_graph.nodes(data=True):
        if not ('node_type' in node.keys() and 'label' in node.keys()):
            node_to_remove.append(n_id)
            continue
        # print(node['label'])
        try:
            first_line = int(node['label'].split('-')[-2])
            last_line = int(node['label'].split('-')[-1])
            code_line = list(range(first_line, last_line+1))
            source_lines[n_id] = {'node_source_code_lines': code_line}
            node_info[n_id] = {'node_info_vulnerabilities': None}
        except (ValueError, IndexError) as e:
            node_to_remove.append(n_id)
    
    cfg_graph.remove_nodes_from(node_to_remove)
    nx.set_node_attributes(cfg_graph, source_lines)
    return cfg_driver.graph


if __name__ == '__main__':
    src_language = 'solidity'
    CFG_output = 'test_source/ERC20Token.dot'
    source_file = 'test_source/ERC20Token.sol'
    cleaned_source_file = 'test_source/ERC20Token_cleaned.sol'
    with open(source_file, 'r') as file_handle:
        src_code = file_handle.read()
    parser = ParserDriver(src_language, src_code)
    cleaned_src_code = parser.src_code
    src_code_lines = cleaned_src_code.split('\n')
    with open(cleaned_source_file, 'w') as f:
        f.write(cleaned_src_code)

    cfg_driver = CFGDriver(src_language, cleaned_src_code, CFG_output)