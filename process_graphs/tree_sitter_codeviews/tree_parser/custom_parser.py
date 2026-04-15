from tree_sitter import Language, Parser, Node
import os
from pathlib import Path
from threading import Lock

# Module-level cache for compiled language library
_language_library_path = None
_language_map = None
_init_lock = Lock()


def _get_library_path():
    """Get the path for the compiled language library."""
    # Use environment variable if set, otherwise use build directory
    lib_dir = os.environ.get('TREE_SITTER_LIB_DIR', 'build')
    return os.path.join(lib_dir, 'my-languages.so')


def _get_vendor_paths():
    """Get paths to tree-sitter vendor directories."""
    # Support both relative and absolute paths
    base_paths = [
        Path("app/sco/process_graphs/tree_sitter_codeviews/vendor"),
        Path("/app/app/sco/process_graphs/tree_sitter_codeviews/vendor"),
    ]
    
    languages = [
        # "tree-sitter-java",
        # "tree-sitter-c-sharp", 
        # "tree-sitter-ruby",
        # "tree-sitter-go",
        # "tree-sitter-php",
        # "tree-sitter-python",
        # "tree-sitter-javascript",
        "tree-sitter-solidity",
    ]
    
    # Find the base path that exists
    for base_path in base_paths:
        if base_path.exists():
            return [str(base_path / lang) for lang in languages]
    
    # Fallback to relative paths
    return [f"app/sco/process_graphs/tree_sitter_codeviews/vendor/{lang}" for lang in languages]


def _initialize_languages():
    """Initialize and cache the language library (thread-safe, called once)."""
    global _language_library_path, _language_map
    
    with _init_lock:
        # Double-check after acquiring lock
        if _language_map is not None:
            return _language_library_path, _language_map
        
        _language_library_path = _get_library_path()
        
        # Ensure the directory exists
        lib_dir = os.path.dirname(_language_library_path)
        if lib_dir:
            os.makedirs(lib_dir, exist_ok=True)
        
        # Only build if the library doesn't exist
        if not os.path.exists(_language_library_path):
            vendor_paths = _get_vendor_paths()
            Language.build_library(_language_library_path, vendor_paths)
        
        # Load languages from compiled library
        _language_map = {
            # "python": Language(_language_library_path, "python"),
            # "java": Language(_language_library_path, "java"),
            # "c_sharp": Language(_language_library_path, "c_sharp"),
            # "ruby": Language(_language_library_path, "ruby"),
            # "go": Language(_language_library_path, "go"),
            # "php": Language(_language_library_path, "php"),
            # "javascript": Language(_language_library_path, "javascript"),
            "solidity": Language(_language_library_path, "solidity"),
        }
        
        return _language_library_path, _language_map


class CustomParser:
    """Custom parser for the src_language"""

    def __init__(self, src_language, src_code):
        """
        Initialize the parser with the language.
        Language options are: python, java, c_sharp, ruby, go, php, javascript, solidity
        """
        self.src_language = src_language
        self.src_code = src_code
        self.index = {}

        # Use cached/pre-compiled language library
        _, self.language_map = _initialize_languages()
        
        self.root_node = self.parse()
        self.all_tokens = []
        self.label = {}
        self.method_map = []
        self.start_line = {}

    def create_AST_id(self, root_node, AST_index, AST_id):
        """ Create an id for each node in the AST. This AST id is maintained and used across all code views so that it is possible to easily combine graphs """
        if root_node.is_named:
            current_node_id = AST_id[0]
            AST_id[0] += 1
            AST_index[(root_node.start_point, root_node.end_point, root_node.type)] = current_node_id
            for child in root_node.children:
                if child.is_named:
                    self.create_AST_id(child, AST_index, AST_id)
            return

    def parse(self):
        parser = Parser()  # tree-sitter parser
        parser.set_language(self.language_map[self.src_language])
        tree = parser.parse(bytes(self.src_code, "utf8"))
        self.root_node = tree.root_node
        # First few id values are reserved for special nodes such as start and end node
        self.create_AST_id(self.root_node, self.index, [5])
        return self.root_node

