from flask import Flask, render_template, request
import os
import re  # שימוש עם ביטויים רגולרים כדי שנוכל לבדוק את הדומיין
import requests  # שולח בקשות לאתר שאנחנו רוצים לאתר ונותן לנו את התוכן שלו כדי שנוכל לנתח אותו
import whois   # מידע על מתי האתר נוצר וכו
import datetime 
from bs4 import BeautifulSoup   # ניתוח דף האתר HTML 
from urllib.parse import urlparse # פירוק היואראל לחלקים נפרדים למשל של הדומיין, הפרוטוקול וכו

app = Flask(__name__)

def is_phishing(url):
    global cause_of_error 
    cause_of_error = []

    global score
    score = 0

    global phishing_score
    phishing_score = 2     

    try:
        response = requests.get(url, timeout=10)   # שליחת בקשת גט לאתר, אם לא קיבלנו תשובה תוך 10 שניות אז הבקשה תיכשל
        content = response.text # אחסון תוכן האתר במשתנה
    except requests.exceptions.RequestException as e:  # במידה ולא נצליח להתחבר לאתר בגלל שגיאות חיבור או כתובת לא חוקית נחזיר שגיאה
        cause_of_error.append("there is an error to fetching the URL")
        return True

    soup = BeautifulSoup(content, 'html.parser')  # שימוש בשני ארגומנטים - התוכן של דף היואראל שניתחנו מקודם, וכלי ניתוח של ביוטיפול סופ עם HTML המובנה שלו
    text_content = soup.get_text()  # הוצאת הטקסט נטו מהדף ומחיקת התגיות של הHTML 

    try:
        parsed_url = urlparse(url)  # פירוק היואראל לחלקים נפרדים למשל של הדומיין, הפרוטוקול וכו
        domain_name = parsed_url.netloc
        
        if domain_name.startswith('www.'):
            domain_name = domain_name[4:]     # הסרת הדאבליו דאבליו דאבליו מהדומיין אם קיים
        
        domain_info = whois.whois(domain_name)  # קבלת מידע על הדומיין כמו תאריך יצירה, תאריך תפוגה וכו
        creation_date = domain_info.creation_date  # שמירת התאריך בו הדומיין נוצר לראשונה
        if isinstance(creation_date, list):  
            creation_date = creation_date[0]   # בדיקה האם התאריך מוצג כרשימה (כי יכול להיות שנרשם כמה פעמים) ואם כן ניקח את הרשומה הראשונה ונתייחס אליה כתאריך היצירה בפועל
        age = (datetime.datetime.now() - creation_date).days  #חישוב גיל הדומיין על ידי חיסור היום שבו נוצר מהיום הנוכחי שאנחנו נמצאים בו
    except Exception as e:  # במידה ולא נצליח לקבל את מידע הדומיין נחזיר שגיאה
        age = None
        cause_of_error.append("Unable to fetch domain details")
        return True

    ############################### RULES #########################################

    # Rule 1: בדיקה האם הדומיין חדש
    if age is not None and age < 30:  # Less than 30 days old
        cause_of_error.append(f"The domain is very new, created on {creation_date.strftime('%Y-%m-%d')}")
        score += 1
    
    # Rule 2: בדיקה אם האתר משתמש ב-SSL
    if "https" not in url:
        cause_of_error.append("The website does not use SSL")
        score += 1
    
    # Rule 3: בדיקת אורך ה-URL
    if len(url) > 75:
        cause_of_error.append("The URL is too long")
        score += 1

    # Rule 4: שימוש בתווים מיוחדים
    suspicious_chars = ['@', '%', '#']
    if any(char in url for char in suspicious_chars):
        cause_of_error.append("The URL contains suspicious characters")
        score += 1

    # Rule 5: בדיקה האם יש מספרים בדומיין
    if re.search(r'\d', domain_name):  # אם מכיל מספרים 0-9
        if not (domain_name.endswith(".co.il") or domain_name.endswith(".org") or domain_name.endswith(".net")): #ולא מסתיים כך 
            cause_of_error.append("The domain name contains some numbers")
            score += 1

    # Rule 6: בדיקת תווים לא סטנדרטיים
    if not all(ord(char) < 128 for char in url): # é ö ± © 我 ك 😊 🔥 
        cause_of_error.append("The URL contains non-ASCII characters")
        score += 1

    # Rule 7: בדיקה אם שם הדומיין זה מספר איי פי
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(domain_name):
        cause_of_error.append("The URL contains an IP address")
        score += 1

    # Rule 8: בדיקת מילים חשודות בתוכן האתר
    suspicious_words = ['verify', 'account', 'update', 'confirm', 'secure']
    if any(word in text_content.lower() for word in suspicious_words):
        cause_of_error.append("Suspicious words found in the content")
        score += 1

    # Rule 9: בדיקת קישורים בתוך האתר
    links = soup.find_all('a')
    links_count=0
    for link in links:
        href = link.get('href')
        if href and domain_name not in href:
            links_count += 1
    if links_count > 6:
        cause_of_error.append("The website has a high number of external suspicious links")
        score += 1

    # Rule 10: בדיקת סיומת הקישור
    suspicious_extensions = ['.exe', '.scr', '.zip', '.rar', '.js', '.apk']
    if any(url.endswith(ext) for ext in suspicious_extensions):
        cause_of_error.append(f"The URL has a suspicious file extension")
        score += 1

    # Rule 11: בדיקת קידודים
    encoded_chars = ['%20', '%22', '%27', '%3C', '%3E', '%2F', '%5C', '%7C']  
    # 20% רווח
    # 22% מרכאות כפולים "
    # 27% מרכאות בודד '
    # %3c קטן מ >
    # %3e גדול מ <
    # %2f קו נטוי /
    # %5c באקסלאש \
    # %7c קו נטוי|
    if any(encoded_char in url for encoded_char in encoded_chars):
        cause_of_error.append("The URL contains encoded characters, which may be suspicious")
        score += 1

    # Rule 12: בדיקת כמות מקפים
    if domain_name.count('-') > 3:
        cause_of_error.append("The domain name contains too many hyphens")
        score += 1

    if score >= phishing_score:
        return True
    return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        result = is_phishing(url)
        if result:
            cause_of_error_str = ', '.join(cause_of_error)
            return render_template('phishingSite.html', url=url, result='Phishing', reason=cause_of_error_str)
        else:
            return render_template('goodSite.html', url=url, result='Secure', reason="This site is secure.")
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))