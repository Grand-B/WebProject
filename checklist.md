1. Test Login/logout function - CHecked
2. Test check pasword function - Checked
3. Test registered function - Checked
4. Check newly registered users privileges - Checked
5. Test feedback field - Checked
6. Check if feedback field store data - Checked
7. Check if users table stored data - Checked
8. Check if privileges table is set up correctly - Checked
9. Test if login password require certain length/symbols - Checked
10. Check if weak password demonstrate warning message - Checked
11. Check if register password require certain length/symbols - Checked
12. Check if weak register password demonstrate warning message - Need implementation, show which symbol is allowed

Security Testing:
1. Check if SQL injection fails at login page - CHecked
2. Check if SQL injection fails at register page - Checked
3. Check if SQL injection fails at feedback page 
4. Check if XSS attack at feedback forum fails 
5. Test if change password fail to accept empty password - checked
6. Test if login fails without valid credentials - Checked
7. Test if common password fails - Checked
8. Change password doesn't check if the current password is correct, need implementation to ensure that it is correct before making the new password the correct password