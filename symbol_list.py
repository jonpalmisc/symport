import csv
from typing import Dict


class SymbolList:
    symbols: Dict

    def __init__(self) -> None:
        self.symbols = {}

    def __iter__(self):
        return self.symbols.__iter__()

    def __getitem__(self, k):
        return self.symbols.__getitem__(k)

    def insert(self, address: int, name: str) -> None:
        """Insert a symbol into the list."""

        self.symbols[address] = name

    def save_csv(self, path: str) -> None:
        """Save the symbol list to a CSV file."""

        with open(path, "w") as f:
            writer = csv.writer(f)

            for address in self.symbols:
                writer.writerow([address, self.symbols[address]])

    def load_csv(self, path: str) -> None:
        """Load the symbol list from a CSV file."""

        with open(path, "r") as f:
            reader = csv.reader(f)

            for row in reader:
                self.symbols[int(row[0])] = row[1]
