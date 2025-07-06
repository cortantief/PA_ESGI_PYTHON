from typing import Self, List
from anytree import NodeMixin, find


class WebNode:
    path: str = ""
    protected: bool = False
    vuln_found: List[str] = []
    params = {}


class WebTree(WebNode, NodeMixin):
    def __init__(self, path: str, parent=None, children: List[Self] = None):
        super(WebNode, self).__init__()
        self.parent = parent
        self.path = path
        if children:
            self.children = children

    def __str__(self):
        return self.path if not self.protected else f"{self.path} / Protected"

    def __repr__(self):
        return self.path if not self.params or len(self.params) == 0 else f"{self.path} / has params"

    def find_by_path(self, path: str) -> Self | None:
        node: Self = None
        if not path:
            return node
        for p in path.strip("/").split("/"):
            node = find(self if node == None else node,
                        lambda x: x.path == p, maxlevel=2)
            if node == None:
                return node
        return node

    def add(self, path: str) -> Self | None:
        if not path:
            return None
        path_comp = path.strip("/").split("/")
        parent = self
        for p in path_comp[:-1]:
            node = parent.find_by_path(p)
            if node == None:
                node = WebTree(p, parent=parent)
            parent = node
        node = parent.find_by_path(path_comp[-1])
        if node:
            return node
        return WebTree(path_comp[-1], parent=parent)
