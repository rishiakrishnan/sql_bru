from openpyxl import Workbook

def create_malicious_xlsx(filename):
    # Create a new Workbook
    wb = Workbook()
    
    # Add a sheet
    ws = wb.active
    ws.title = "Malicious Data"
    
    # Add suspicious content
    suspicious_content = [
        "SELECT * FROM users WHERE username = 'admin';",
        "DROP TABLE users;",
        "eval('some malicious code');"
    ]
    
    for index, line in enumerate(suspicious_content, start=1):
        ws[f'A{index}'] = line
    
    # Add suspicious metadata
    wb.properties.title = "Malicious Excel Document"
    wb.properties.keywords = "script, eval, base64"
    
    # Save the workbook
    wb.save(filename)
    print(f"Malicious .xlsx file '{filename}' created successfully.")

# Create a malicious .xlsx file
create_malicious_xlsx('malicious.xlsx')
