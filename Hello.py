# Copyright (c) Streamlit Inc. (2018-2022) Snowflake Inc. (2022)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import streamlit as st
from streamlit.logger import get_logger
from PIL import Image

LOGGER = get_logger(__name__)


def run():
    st.set_page_config(
        page_title="Hello",
        page_icon="👋",
    )

    st.title("GROUP 11")


    st.write("Members:")
    st.write("1. Brigola, Randolf")
    st.write("2. Dimanarig, Arjun Rashid L.")
    st.write("3. Periabras, Ellyza")


    st.markdown("---")

    st.write("Introduction")

    st.write("  This project is focused on creating an application that implements different cryptographic techniques to ensure secure communication, data, and information exchange. The goal is to make the application user-friendly and accessible. Cryptography is essential for maintaining the security and trustworthiness of messages and data in today's world. This application offers a user-friendly interface for encrypting, decrypting, and hashing messages or files using various cryptographic algorithms.")



if __name__ == "__main__":
    run()
