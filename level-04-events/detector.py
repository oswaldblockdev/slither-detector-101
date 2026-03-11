from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import EventCall
from pathlib import Path
import os

class EventEmissionDetector(AbstractDetector):
    ARGUMENT = 'check-events'
    HELP = 'Flag state-changing balance updates missing events via IR analysis'
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://github.com/your-repo/wiki/level4'
    WIKI_TITLE = 'Missing Event Emission (IR Check)'
    WIKI_DESCRIPTION = 'This detector manually inspects SlithIR operations to ensure balance updates are accompanied by an EventCall.'
    WIKI_EXPLOIT_SCENARIO = 'Off-chain systems rely on IR-level Emit instructions to catch state changes.'
    WIKI_RECOMMENDATION = 'Ensure an emit statement is present in the CFG for every sensitive state change.'

    def _detect(self):
        # 1. Identify if a 'balance' variable is written to
        # 2. Manually count Emit operations by inspecting IRs in all nodes
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                if func.view or func.pure or func.is_constructor:
                    continue

                balance_writes = [v for v in func.state_variables_written if 'balance' in v.name.lower()] # type: ignore
                
                if balance_writes:
                    has_event_call = False
                    for node in func.nodes:
                        for ir in node.irs:
                            # Slither represents 'emit MyEvent(...)' as an EventCall operation
                            if isinstance(ir, EventCall):
                                has_event_call = True
                                break
                        if has_event_call:
                            break

                    # 3. If balance was touched but no EventCall IR found
                    if not has_event_call:
                        info = [f"Warning: {func.name} in {contract.name} updates {balance_writes[0].name} but no Emit IR found!\n"]
                        res = self.generate_result(info) # type: ignore
                        results.append(res)
        return results

if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    vulnerable_sol = os.path.join(current_dir, "Vulnerable.sol")
    
    if not os.path.exists(vulnerable_sol):
        print(f"❌ Error: {vulnerable_sol} not found.")
    else:
        print(f"🔍 Analyzing IRs in: {vulnerable_sol}")
        slither = Slither(vulnerable_sol)
        slither.register_detector(EventEmissionDetector)
        results = slither.run_detectors()
        
        found = False
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")
                found = True
        
        if not found:
            print("✅ All balance updates have corresponding Emit IRs.")