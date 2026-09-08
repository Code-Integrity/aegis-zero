def format_depth4_tree(tree):
"""Format Depth4 tree for readability."""
return {
"node_count": len(tree),
"nodes": tree
}

def format_llama_payload(prompt_file, model_path, tree, scoring):
"""Prepare payload for LLaMA inference."""
return {
"prompt_file": prompt_file,
"model_path": model_path,
"depth4_tree": tree,
"scoring": scoring
}