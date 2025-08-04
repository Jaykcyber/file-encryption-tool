<full file content with the following changes>

1. Add the about_section() function:
def about_section():
    st.header("👥 About EncryptEase Team")
    st.markdown("""
    **Team Name:** EncryptEase  
    **Total Members:** 4

    **Members:**
    - Jay Kumar
    - Akaisha Sundhan
    - Badal Pal
    - Dhaval Thakker
    """)
    st.info("Built with ❤️ by EncryptEase for secure file encryption.")

2. Change this line:
tab1, tab2, tab3 = st.tabs(["🔒 Encrypt File", "🔓 Decrypt File", "ℹ️ File Info"])
to:
tab1, tab2, tab3, tab4 = st.tabs(["🔒 Encrypt File", "🔓 Decrypt File", "ℹ️ File Info", "👥 About"])

3. Add this inside main():
with tab4:
    about_section()