from __future__ import annotations

import copy
import warnings
from abc import abstractmethod
from typing import Any, Callable

from wikibaseintegrator.models.basemodel import BaseModel
from wikibaseintegrator.models.qualifiers import Qualifiers
from wikibaseintegrator.models.references import Reference, References
from wikibaseintegrator.models.snaks import Snak, Snaks
from wikibaseintegrator.wbi_enums import ActionIfExists, WikibaseRank, WikibaseSnakType

# Normalizer functions
def normalize_snak(snak):
    """
    Normalize a snak. Handles both Snak objects and dictionary representations.

    Args:
        snak (Snak | dict): A snak object or a dictionary representing a snak.

    Returns:
        dict: A normalized dictionary representation of the snak.
    """
    if isinstance(snak, dict):
        # Already a dictionary; just ensure it contains the expected keys
        return {
            "snaktype": snak.get("snaktype"),
            "property": snak.get("property"),
            "datavalue": snak.get("datavalue"),
        }
    else:
        # Assume it's a Snak object
        return {
            "snaktype": snak.snaktype,
            "property": snak.property_number,
            "datavalue": snak.datavalue,
        }


def normalize_reference(reference):
    """
    Normalize a reference by excluding `snaks-order` and normalizing its snaks.

    Args:
        reference (dict): A dictionary representing a reference.

    Returns:
        dict: A normalized dictionary representation of the reference.
    """
    return {
        "snaks": {
            prop: [normalize_snak(snak) for snak in snaks]
            for prop, snaks in reference["snaks"].items()
        }
    }

class Claims(BaseModel):
    def __init__(self) -> None:
        self.claims: dict[str, list[Claim]] = {}

    @property
    def claims(self) -> dict[str, list[Claim]]:
        return self.__claims

    @claims.setter
    def claims(self, claims: dict[str, list[Claim]]):
        self.__claims = claims

    def get(self, property: str | int) -> list[Claim]:
        if isinstance(property, int):
            property = 'P' + str(property)

        if property in self.claims:
            return self.claims[property]

        return []

    def remove(self, property: str | None = None) -> None:
        if property in self.claims:
            for prop in self.claims[property]:
                if prop.id:
                    prop.remove()
                else:
                    self.claims[property].remove(prop)
            if len(self.claims[property]) == 0:
                del self.claims[property]

    def add(self, claims: Claims | list[Claim] | Claim, action_if_exists: ActionIfExists = ActionIfExists.REPLACE_ALL) -> Claims:
        """

        :param claims: A Claim, list of Claim or just a Claims object to add to this Claims object.
        :param action_if_exists: Replace or append the statement. You can force an addition if the declaration already exists. Defaults to REPLACE_ALL.
            KEEP: The original claim will be kept and the new one will not be added (because there is already one with this property number)
            APPEND_OR_REPLACE: The new claim will be added only if the new one is different (by comparing values)
            FORCE_APPEND: The new claim will be added even if already exists
            REPLACE_ALL: The new claim will replace the old one
        :return: Return the updated Claims object.
        """

        if action_if_exists not in ActionIfExists:
            raise ValueError(f'{action_if_exists} is not a valid action_if_exists value. Use the enum ActionIfExists')

        if isinstance(claims, Claim):
            claims = [claims]
        elif claims is None or ((not isinstance(claims, list) or not all(isinstance(n, Claim) for n in claims)) and not isinstance(claims, Claims)):
            raise TypeError("claims must be an instance of Claim or Claims or a list of Claim")

        # TODO: Don't replace if claim is the same
        # This code is separated from the rest to avoid looping multiple over `self.claims`.
        if action_if_exists == ActionIfExists.REPLACE_ALL:
            for claim in claims:
                if claim is not None:
                    assert isinstance(claim, Claim)

                    property = claim.mainsnak.property_number
                    if property in self.claims:
                        for claim_to_remove in self.claims[property]:
                            if claim_to_remove not in claims:
                                claim_to_remove.remove()

        for claim in claims:
            if claim is not None:
                assert isinstance(claim, Claim)
                property = claim.mainsnak.property_number

                if property not in self.claims:
                    self.claims[property] = []

                if action_if_exists == ActionIfExists.KEEP:
                    if len(self.claims[property]) == 0:
                        self.claims[property].append(claim)
                elif action_if_exists == ActionIfExists.FORCE_APPEND:
                    self.claims[property].append(claim)
                elif action_if_exists == ActionIfExists.APPEND_OR_REPLACE:
                    if claim not in self.claims[property]:
                        self.claims[property].append(claim)
                    else:
                        # Force update the claim if already present
                        self.claims[property][self.claims[property].index(claim)].update(claim)
                elif action_if_exists == ActionIfExists.REPLACE_ALL:
                    if claim not in self.claims[property]:
                        self.claims[property].append(claim)
                elif action_if_exists == ActionIfExists.MERGE_REFS_OR_APPEND:
                    claim_exists = False
                    for existing_claim in self.claims[property]:
                        existing_claim_json = existing_claim.get_json()
                        claim_to_add_json = claim.get_json()
                        # Check if the values match, including qualifiers
                        if "datavalue" in claim_to_add_json["mainsnak"] and "datavalue" in existing_claim_json["mainsnak"]:
                            if (claim_to_add_json["mainsnak"]["datavalue"]["value"] == existing_claim_json["mainsnak"]["datavalue"]["value"]):
                                if existing_claim.has_equal_qualifiers(claim):
                                  claim_exists = True
                        if "datavalue" not in claim_to_add_json["mainsnak"] and "datavalue" not in existing_claim_json["mainsnak"]:
                            # Both are blank nodes, checking qualifiers    
                            if claim.quals_equal(claim, existing_claim):
                                claim_exists = True

                        if claim_exists:
                                # Check if current reference block is present on references
                                if not Claim.ref_present(newitem=claim, olditem=existing_claim):
                                    for ref_to_add in claim.references:
                                        if ref_to_add not in existing_claim.references:
                                            existing_claim.references.add(ref_to_add)
                                break

                    # If the claim value does not exist, append it
                    if not claim_exists:
                        self.claims[property].append(claim)
        return self

    def from_json(self, json_data: dict[str, Any]) -> Claims:
        for property in json_data:
            for claim in json_data[property]:
                from wikibaseintegrator.datatypes import BaseDataType
                if 'datatype' in claim['mainsnak']:
                    data_type = [x for x in BaseDataType.subclasses if x.DTYPE == claim['mainsnak']['datatype']][0]
                else:
                    data_type = BaseDataType
                self.add(claims=data_type().from_json(claim), action_if_exists=ActionIfExists.FORCE_APPEND)

        return self

    def get_json(self) -> dict[str, list]:
        json_data: dict[str, list] = {}
        for property, claims in self.claims.items():
            if property not in json_data:
                json_data[property] = []
            for claim in claims:
                if not claim.removed or claim.id:
                    json_data[property].append(claim.get_json())
            if len(json_data[property]) == 0:
                del json_data[property]
        return json_data

    def __iter__(self):
        iterate = []
        for claim in self.claims.values():
            iterate.extend(claim)
        return iter(iterate)

    def __len__(self):
        return len(self.claims)


class Claim(BaseModel):
    DTYPE = 'claim'

    def __init__(self, qualifiers: Qualifiers | None = None, rank: WikibaseRank | None = None, references: References | list[Claim | list[Claim]] | None = None,
                 snaktype: WikibaseSnakType = WikibaseSnakType.KNOWN_VALUE) -> None:
        """

        :param qualifiers:
        :param rank:
        :param references: A References object, a list of Claim object or a list of list of Claim object
        :param snaktype:
        """
        self.mainsnak = Snak(datatype=self.DTYPE, snaktype=snaktype)
        self.type = 'statement'
        self.qualifiers = qualifiers or Qualifiers()
        self.qualifiers_order = []
        self.id = None
        self.rank = rank or WikibaseRank.NORMAL
        self.removed = False

        self.references = References()

        if isinstance(references, References):
            self.references = references
        elif isinstance(references, list):
            for ref_list in references:
                ref = Reference()
                if isinstance(ref_list, list):
                    snaks = Snaks()
                    for ref_claim in ref_list:
                        if isinstance(ref_claim, Claim):
                            snaks.add(Snak().from_json(ref_claim.get_json()['mainsnak']))
                        else:
                            raise ValueError("The references must be a References object or a list of Claim object")
                    ref.snaks = snaks
                elif isinstance(ref_list, Claim):
                    ref.snaks = Snaks().add(Snak().from_json(ref_list.get_json()['mainsnak']))
                elif isinstance(ref_list, Reference):
                    ref = ref_list
                self.references.add(reference=ref)
        elif references is not None:
            raise ValueError("The references must be a References object or a list of Claim object")

    @property
    def mainsnak(self) -> Snak:
        return self.__mainsnak

    @mainsnak.setter
    def mainsnak(self, value: Snak):
        self.__mainsnak = value

    @property
    def type(self) -> str | dict:
        return self.__type

    @type.setter
    def type(self, value: str | dict):
        self.__type = value

    @property
    def qualifiers(self) -> Qualifiers:
        return self.__qualifiers

    @qualifiers.setter
    def qualifiers(self, value: Qualifiers) -> None:
        assert isinstance(value, (Qualifiers, list))
        self.__qualifiers: Qualifiers = Qualifiers().set(value) if isinstance(value, list) else value

    @property
    def qualifiers_order(self) -> list[str]:
        return self.__qualifiers_order

    @qualifiers_order.setter
    def qualifiers_order(self, value: list[str]):
        self.__qualifiers_order = value

    @property
    def id(self) -> str | None:
        return self.__id

    @id.setter
    def id(self, value: str | None):
        self.__id = value

    @property
    def rank(self) -> WikibaseRank:
        return self.__rank

    @rank.setter
    def rank(self, value: WikibaseRank):
        """Parse the rank. The enum throws an error if it is not one of the recognized values"""
        self.__rank = WikibaseRank(value)

    @property
    def references(self) -> References:
        return self.__references

    @references.setter
    def references(self, value: References):
        self.__references = value

    @property
    def removed(self) -> bool:
        return self.__removed

    @removed.setter
    def removed(self, value: bool):
        self.__removed = value

    def remove(self, remove=True) -> None:
        self.removed = remove

    def update(self, claim: Claim) -> None:
        self.mainsnak = claim.mainsnak
        self.qualifiers = claim.qualifiers
        self.qualifiers_order = claim.qualifiers_order
        self.rank = claim.rank
        self.references = claim.references

    def from_json(self, json_data: dict[str, Any]) -> Claim:
        """

        :param json_data: a JSON representation of a Claim
        """
        self.mainsnak = Snak().from_json(json_data['mainsnak'])
        self.type = str(json_data['type'])
        if 'qualifiers' in json_data:
            self.qualifiers = Qualifiers().from_json(json_data['qualifiers'])
        if 'qualifiers-order' in json_data:
            self.qualifiers_order = list(json_data['qualifiers-order'])
        self.id = str(json_data['id'])
        self.rank: WikibaseRank = WikibaseRank(json_data['rank'])
        if 'references' in json_data:
            self.references = References().from_json(json_data['references'])

        return self

    def get_json(self) -> dict[str, Any]:
        json_data: dict[str, str | list[dict] | list[str] | dict[str, str] | dict[str, list] | None] = {
            'mainsnak': self.mainsnak.get_json(),
            'type': self.type,
            'id': self.id,
            'rank': self.rank.value
        }
        # Remove id if it's a temporary one
        if not self.id:
            del json_data['id']
        if len(self.qualifiers) > 0:
            json_data['qualifiers'] = self.qualifiers.get_json()
            json_data['qualifiers-order'] = list(self.qualifiers_order)
        if len(self.references) > 0:
            json_data['references'] = self.references.get_json()
        if self.removed:
            if self.id:
                json_data['remove'] = ''
        return json_data

    def has_equal_qualifiers(self, other: Claim) -> bool:
        """Compare qualifiers with another claim, ignoring datatype and qualifiers-order."""
        # Access the underlying dictionary of qualifiers
        self_qualifiers = self.qualifiers.qualifiers  # Access the dictionary
        other_qualifiers = other.qualifiers.qualifiers  # Access the dictionary
        # Check if both have the same properties
        if set(self_qualifiers.keys()) != set(other_qualifiers.keys()):
            return False

        # Check if all qualifiers for each property match
        for property_number, self_snaks in self_qualifiers.items():
            if property_number not in other_qualifiers:
                return False

            other_snaks = other_qualifiers[property_number]

            # Check if the number of Snaks is the same
            if len(self_snaks) != len(other_snaks):
                return False

            normalized_self_snaks = [normalize_snak(s) for s in self_snaks]
            normalized_other_snaks = [normalize_snak(s) for s in other_snaks]

            # Ensure all Snaks in self are in other
            if not all(s in normalized_other_snaks for s in normalized_self_snaks):
                return False

        return True

    def reset_id(self):
        """
        Reset the ID of the current claim
        """
        self.id = None

    # TODO: rewrite this?
    def __contains__(self, item):
        if isinstance(item, Claim):
            return self == item

        if isinstance(item, str):
            return self.mainsnak.datavalue == item

        return super().__contains__(item)

    def __eq__(self, other):
        if isinstance(other, Claim):
            return self.mainsnak.datavalue == other.mainsnak.datavalue and self.mainsnak.property_number == other.mainsnak.property_number and self.has_equal_qualifiers(other)

        if isinstance(other, str):
            return self.mainsnak.property_number == other

        raise super().__eq__(other)

    def equals(self, that: Claim, include_ref: bool = False, fref: Callable | None = None) -> bool:
        """
        Tests for equality of two statements.
        If comparing references, the order of the arguments matters!!!
        self is the current statement, the next argument is the new statement.
        Allows passing in a function to use to compare the references 'fref'. Default is equality.
        fref accepts two arguments 'oldrefs' and 'newrefs', each of which are a list of references,
        where each reference is a list of statements
        """

        if not include_ref:
            # return the result of BaseDataType.__eq__, which is testing for equality of value and qualifiers
            return self == that

        if self != that:
            return False

        if fref is None:
            return Claim.refs_equal(self, that)

        return fref(self, that)

    @staticmethod
    def quals_equal(olditem: Claim, newitem: Claim) -> bool:
        """
        Tests for exactly identical qualifiers.
        """

        oldqual = olditem.qualifiers
        newqual = newitem.qualifiers

        return (len(oldqual) == len(newqual)) and all(x in oldqual for x in newqual)

    @staticmethod
    def refs_equal(olditem: Claim, newitem: Claim) -> bool:
        """
        tests for exactly identical references
        """

        oldrefs = olditem.references
        newrefs = newitem.references

        def ref_equal(oldref: References, newref: References) -> bool:
            return (len(oldref) == len(newref)) and all(x in oldref for x in newref)

        return len(oldrefs) == len(newrefs) and all(any(ref_equal(oldref, newref) for oldref in oldrefs) for newref in newrefs)

    @staticmethod
    def ref_present(olditem: Claim, newitem: Claim) -> bool:
        """
        Tests if (1) there is a single ref in the new item and
        (2) if this single ref is present among the claims of the old item.
        """

        oldrefs = olditem.references
        newrefs = newitem.references

        if len(newrefs) != 1:
            warnings.warn("New item has more or less than 1 reference block.")
            return False

        def ref_equal(oldref, newref):
            """Compare two references, ignoring snaks-order and datatype."""

            normalized_oldref = normalize_reference(oldref)
            normalized_newref = normalize_reference(newref)

            return normalized_oldref == normalized_newref

        for newref in newrefs:
            for oldref in oldrefs:
                if ref_equal(oldref.get_json(), newref.get_json()):
                    return True
        return False

    @abstractmethod
    def get_sparql_value(self) -> str:
        pass