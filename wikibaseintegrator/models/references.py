from __future__ import annotations

from typing import Optional

from wikibaseintegrator.models.snaks import Snaks


class References:
    def __init__(self):
        self.references = []

    def get(self, hash=None):
        for reference in self.references:
            if reference.hash == hash:
                return reference
        return None

    def add(self, reference: Optional[Reference] = None, if_exists='REPLACE'):
        if reference is not None:
            assert isinstance(reference, Reference)

        if reference not in self.references:
            self.references.append(reference)

        return self

    def from_json(self, json_data) -> References:
        for reference in json_data:
            self.add(reference=Reference().from_json(reference))

        return self

    def get_json(self) -> []:
        json_data = []
        for reference in self.references:
            json_data.append(reference.get_json())
        return json_data

    def __len__(self):
        return len(self.references)

    def __repr__(self):
        """A mixin implementing a simple __repr__."""
        return "<{klass} @{id:x} {attrs}>".format(
            klass=self.__class__.__name__,
            id=id(self) & 0xFFFFFF,
            attrs=" ".join("{}={!r}".format(k, v) for k, v in self.__dict__.items()),
        )


class Reference:
    def __init__(self):
        self.hash = None
        self.snaks = Snaks()
        self.snaks_order = []

    @property
    def hash(self):
        return self.__hash

    @hash.setter
    def hash(self, value):
        self.__hash = value

    @property
    def snaks(self):
        return self.__snaks

    @snaks.setter
    def snaks(self, value):
        self.__snaks = value

    @property
    def snaks_order(self):
        return self.__snaks_order

    @snaks_order.setter
    def snaks_order(self, value):
        self.__snaks_order = value

    def from_json(self, json_data) -> Reference:
        self.hash = json_data['hash']
        self.snaks = Snaks().from_json(json_data['snaks'])
        self.snaks_order = json_data['snaks-order']

        return self

    def get_json(self) -> {}:
        json_data = {
            'snaks': self.snaks.get_json(),
            'snaks-order': self.snaks_order
        }
        return json_data

    def __repr__(self):
        """A mixin implementing a simple __repr__."""
        return "<{klass} @{id:x} {attrs}>".format(
            klass=self.__class__.__name__,
            id=id(self) & 0xFFFFFF,
            attrs=" ".join("{}={!r}".format(k, v) for k, v in self.__dict__.items()),
        )
