from openpyxl import Workbook
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "fixtures"
book = Workbook()
assets = book.active
assets.title = "Assets"
assets.append(["hostname", "ip_address", "subnet", "device_type", "os", "vlan", "enclave", "department", "owner", "mission_function", "criticality", "maintenance_window", "scan_restrictions"])
assets.append(["SHEET-WIN", "10.8.8.8", "10.8.8.0/24", "workstation", "Windows 11", "8", "SYNTH-ENCLAVE", "Training", "H. Operator", "Training", "medium", "", "synthetic"])
notes = book.create_sheet("Notes")
notes.append(["note"])
notes.append(["Synthetic training workbook. Formulas and macros are intentionally absent."])
book.save(root / "synthetic_inventory.xlsx")
print(root / "synthetic_inventory.xlsx")
