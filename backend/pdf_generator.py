from fpdf import FPDF
import datetime
import os

class RiskReportPDF(FPDF):
    def header(self):
        # Arial bold 15
        self.set_font('Arial', 'B', 15)
        # Title (let width=0 so it spans across to right margin, centered)
        self.cell(0, 10, 'Targeted URL Risk Analysis Report', 0, 0, 'C')
        # Line break
        self.ln(20)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')

def generate_pdf_report(url: str, is_phishing: bool, risk_score: float, risk_factors: list[str]) -> str:
    pdf = RiskReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Set Metadata
    pdf.set_font('Arial', '', 12)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Analysis Date:', 0, 1)
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0, 1)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Analyzed URL:', 0, 1)
    pdf.set_font('Arial', '', 12)
    # Handle long urls by splitting them into smaller chunks manually
    chunk_size = 50
    for i in range(0, len(url), chunk_size):
        pdf.cell(0, 8, url[i:i+chunk_size], 0, 1)
    pdf.ln(5)
    
    # Divider
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    # Results Section
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Detection Result', 0, 1)
    
    status_text = "HIGH RISK (Phishing Detected)" if is_phishing else "LOW RISK (Legitimate)"
    status_color = (255, 0, 0) if is_phishing else (0, 128, 0)
    
    pdf.set_font('Arial', 'B', 14)
    pdf.set_text_color(*status_color)
    pdf.cell(0, 10, f'Status: {status_text}', 0, 1)
    
    pdf.cell(0, 10, f'Risk Score: {risk_score:.1f}%', 0, 1)
    pdf.set_text_color(0, 0, 0) # reset
    pdf.ln(5)
    
    # Risk Factors Section
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Identified Risk Factors & Explanation:', 0, 1)
    
    pdf.set_font('Arial', '', 12)
    if not risk_factors:
        pdf.cell(0, 10, '- No specific risk factors identified.', 0, 1)
    else:
        for factor in risk_factors:
            pdf.write(8, f'- {factor}\n\n')
    
    pdf.ln(10)
    
    # Recommendations
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Safety Recommendations:', 0, 1)
    pdf.set_font('Arial', '', 12)
    
    if is_phishing:
        recs = [
            "Do NOT click on the link or enter any personal information.",
            "Report the URL to your organization's IT security team.",
            "If you have already entered information, change your passwords immediately.",
            "Enable Two-Factor Authentication (2FA) wherever possible."
        ]
    else:
        recs = [
            "The URL appears safe, but always verify the identity of the sender.",
            "Ensure the site uses HTTPS before entering sensitive data.",
            "Look for small typos in the domain name (e.g., google.com vs g00gle.com)."
        ]
        
    for rec in recs:
        pdf.cell(0, 8, f'* {rec}', 0, 1)
        
    # Save PDF
    os.makedirs(os.path.join(os.path.dirname(__file__), 'temp'), exist_ok=True)
    file_name = f"risk_report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    file_path = os.path.join(os.path.dirname(__file__), 'temp', file_name)
    pdf.output(file_path)
    
    return file_path
