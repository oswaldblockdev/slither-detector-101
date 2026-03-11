from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from pathlib import Path
import os

class InterfaceComplianceDetector(AbstractDetector):
    ARGUMENT = 'check-erc20'
    HELP = 'Check if ERC20-like contracts implement transfer correctly'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://github.com/your-repo/wiki/level5'
    WIKI_TITLE = 'Non-Standard ERC20 Implementation'
    WIKI_DESCRIPTION = 'This detector checks if a contract implements the standard ERC20 transfer signature. Deviating from the standard (e.g., missing return bool) can cause integrations like Uniswap or Compound to fail or lock funds.'
    WIKI_EXPLOIT_SCENARIO = 'A contract calls transfer() expecting a boolean return value. If the token returns nothing (void), the calling contract may revert, or worse, interpret the empty stack as "false".'
    WIKI_RECOMMENDATION = 'Follow the IERC20 interface exactly: function transfer(address to, uint256 value) public returns (bool).'

    def _detect(self):
        results = []
        for contract in self.contracts:
            # 1. Heuristic: Only check contracts that look like ERC20s 
            # (e.g., they have a totalSupply state variable)
            has_total_supply: bool = any('totalSupply' in v.name for v in contract.state_variables) # type: ignore
            
            if has_total_supply:
                # 2. Look for the 'transfer' function
                transfer_func = next((f for f in contract.functions if f.name == 'transfer'), None)

                if transfer_func:
                    # 3. Check parameters: should be (address, uint256)
                    params = transfer_func.parameters
                    correct_params = (
                        len(params) == 2 and 
                        str(params[0].type) == 'address' and 
                        str(params[1].type) == 'uint256'
                    )

                    # 4. Check return type: should be (bool)
                    # transfer_func.return_values is a list of types
                    returns = transfer_func.return_values
                    correct_return = len(returns) == 1 and str(returns[0]) == 'bool'

                    if not (correct_params and correct_return):
                        info = [f"Interface Error: {contract.name}.transfer does not match ERC20 standard!\n"]
                        info.append(f"Expected: transfer(address,uint256) -> bool\n")
                        info.append(f"Found: {transfer_func.full_name} -> {returns}\n")
                        
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
        print(f"🔍 Validating Interface in: {vulnerable_sol}")
        slither = Slither(vulnerable_sol)
        slither.register_detector(InterfaceComplianceDetector)
        results = slither.run_detectors()
        
        found = False
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")
                found = True
        
        if not found:
            print("✅ ERC20 interface looks compliant.")