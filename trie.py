# Implementação de uma Trie adaptada de: https://albertauyeung.github.io/2020/06/15/python-trie.html/

class TrieNode:
    def __init__(self, char):
        self.char = char
        self.is_end = False
        self.key = None
        self.children = {}

class Trie(object):
    def __init__(self):
        self.root = TrieNode("")
    
    def insert(self, word, key):
        node = self.root
        if word:
            for char in word:
                if char in node.children:
                    node = node.children[char]
                else:
                    new_node = TrieNode(char)
                    node.children[char] = new_node
                    node = new_node
        node.is_end = True
        node.key = key
        
    def query(self, x):
        node = self.root
        k = self.root.key
        for char in x:
            if char in node.children:
                node = node.children[char]
                if node.key != None:
                    k = node.key
            else:
                break
        if not k:
            return node.key
        else:
            return k
