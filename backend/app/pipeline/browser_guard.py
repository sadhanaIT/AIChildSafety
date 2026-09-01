import winreg

def enforce_browser_safety_locks():
    chrome_policy_path = r"SOFTWARE\Policies\Google\Chrome"
    try:
        reg_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, chrome_policy_path)
        winreg.SetValueEx(reg_key, "ForceGoogleSafeSearch", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(reg_key, "ForceYouTubeRestrict", 0, winreg.REG_DWORD, 2)
        winreg.CloseKey(reg_key)
        return True
    except Exception:
        return False

def remove_browser_safety_locks():
    """Removes the registry policy enforcement to unlock browser settings."""
    chrome_policy_path = r"SOFTWARE\Policies\Google\Chrome"
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, chrome_policy_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(reg_key, "ForceGoogleSafeSearch")
        winreg.DeleteValue(reg_key, "ForceYouTubeRestrict")
        winreg.CloseKey(reg_key)
        print("Success: Browser safety locks have been removed.")
        return True
    except FileNotFoundError:
        print("Policies already removed or not found.")
        return True
    except Exception as e:
        print(f"Error unlocking browser: {e}")
        return False

if __name__ == "__main__":
    remove_browser_safety_locks()