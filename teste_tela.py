import tkinter as tk
from tkinter import messagebox, filedialog
from auth import register_user, login_user
from signature_test import sign_file, verify_signature
from db_helpers import get_user_public_key

def login():
    user = entry_user.get()
    pwd = entry_pass.get()
    if login_user(user, pwd):
        messagebox.showinfo("Login", "Login bem-sucedido!")
        open_main_window(user)
    else:
        messagebox.showerror("Erro", "Usuário ou senha incorretos")

def register():
    user = entry_user.get()
    pwd = entry_pass.get()
    register_user(user, pwd)
    messagebox.showinfo("Registro", "Usuário registrado com sucesso!")

def open_main_window(user):
    login_window.destroy()
    main_window = tk.Tk()
    main_window.title("Sistema de Assinaturas RSA")
    
    def sign_document():
        file_path = filedialog.askopenfilename()
        if file_path:
            success, message = sign_file(user, file_path)
            if success:
                messagebox.showinfo("Assinatura", message)
            else:
                messagebox.showerror("Erro", message)

    def verify_document():
        file_path = filedialog.askopenfilename()
        if file_path:
            username = tk.simpledialog.askstring("Verificação", "Nome do usuário que assinou:")
            public_key = get_user_public_key(username)
            if public_key:
                success, message = verify_signature(file_path, username)
                if success:
                    messagebox.showinfo("Verificação", message)
                else:
                    messagebox.showerror("Erro", message)
            else:
                messagebox.showerror("Erro", "Usuário não encontrado!")
    
    tk.Button(main_window, text="Assinar Documento", command=sign_document).pack(pady=10)
    tk.Button(main_window, text="Verificar Assinatura", command=verify_document).pack(pady=10)
    tk.Button(main_window, text="Sair", command=main_window.quit).pack(pady=10)
    
    main_window.mainloop()

# Criar tela de login
login_window = tk.Tk()
login_window.title("Login - Sistema RSA")

tk.Label(login_window, text="Usuário:").pack()
entry_user = tk.Entry(login_window)
entry_user.pack()

tk.Label(login_window, text="Senha:").pack()
entry_pass = tk.Entry(login_window, show="*")
entry_pass.pack()

tk.Button(login_window, text="Login", command=login).pack(pady=5)
tk.Button(login_window, text="Registrar", command=register).pack(pady=5)

login_window.mainloop()
