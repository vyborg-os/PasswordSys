using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordManager
{
    class Program
    {
        private static string usersFile = "users.txt";
        private static string passwordManagerFile = "passwordManager.txt";
        private static string currentUser;

        static void Main(string[] args)
        {
            UserManagement();
        }

        #region User Management

        private static void UserManagement()
        {
            LoadOrCreateUsersFile();

            while (true)
            {
                Console.WriteLine("1. Login");
                Console.WriteLine("2. Register");
                Console.WriteLine("3. Admin-End");
                Console.WriteLine("0. Exit");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        currentUser = Login();
                        if (currentUser != null)
                        {
                            Console.WriteLine($"Welcome, {currentUser}!");
                            PasswordManagerOperations();
                        }
                        else
                        {
                            Console.WriteLine("Login failed. Please try again.");
                        }
                        break;
                    case "2":
                        Register();
                        break;
                    case "3":
                        AdminEnd();
                        break;
                    case "0":
                        Environment.Exit(0);
                        break;
                    default:
                        Console.WriteLine("Invalid choice. Please try again.");
                        break;
                }
            }
        }

        private static void LoadOrCreateUsersFile()
        {
            if (!File.Exists(usersFile))
            {
                File.Create(usersFile).Close();
            }
        }

        private static void Register()
        {
            Console.WriteLine("Enter a new username:");
            string newUsername = Console.ReadLine();

            if (!UserExists(newUsername))
            {
                Console.WriteLine("Enter a password:");
                string password = ReadPassword();

                using (StreamWriter sw = File.AppendText(usersFile))
                {
                    sw.WriteLine($"{newUsername},{GetHash(password)}");
                }

                Console.WriteLine("Registration successful!");
            }
            else
            {
                Console.WriteLine("Username already exists. Please choose a different one.");
            }
        }

        private static bool UserExists(string username)
        {
            string[] lines = File.ReadAllLines(usersFile);
            foreach (var line in lines)
            {
                var parts = line.Split(',');
                if (parts.Length == 2 && parts[0] == username)
                {
                    return true;
                }
            }
            return false;
        }

        private static string Login()
        {
            Console.WriteLine("Enter your username:");
            string username = Console.ReadLine();

            Console.WriteLine("Enter your password:");
            string password = ReadPassword();

            string[] lines = File.ReadAllLines(usersFile);
            foreach (var line in lines)
            {
                var parts = line.Split(',');
                if (parts.Length == 2 && parts[0] == username && VerifyHash(password, parts[1]))
                {
                    return username;
                }
            }

            return null;
        }

        #endregion

        #region Password Manager Operations

        private static void PasswordManagerOperations()
        {
            while (true)
            {
                Console.WriteLine("1. Add Password");
                Console.WriteLine("2. View Passwords");
                Console.WriteLine("3. Search Passwords");
                Console.WriteLine("4. Sort Passwords by Last Updated Date");
                Console.WriteLine("5. Decrypt Information");
                Console.WriteLine("6. Edit Password");
                Console.WriteLine("7. Delete Password");
                Console.WriteLine("0. Logout");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        AddPassword();
                        break;
                    case "2":
                        ViewPasswords();
                        break;
                    case "3":
                        SearchPasswords();
                        break;
                    case "4":
                        SortPasswordsByLastUpdatedDate();
                        break;
                    case "5":
                        ViewShowInfo();
                        break;
                    case "6":
                        EditPassword();
                        break;
                    case "7":
                        DeletePassword();
                        break;
                    case "0":
                        currentUser = null;
                        Console.WriteLine("Logged out successfully.");
                        UserManagement();
                        break;
                    default:
                        Console.WriteLine("Invalid choice. Please try again.");
                        break;
                }
            }
        }

        private static void AddPassword()
        {
            Console.WriteLine("Enter password type (Website, Desktop, Game):");
            string passwordType = Console.ReadLine();


            Console.WriteLine($"Enter {passwordType} Name:");
            string typename = Console.ReadLine();

            Console.WriteLine("Enter password (or type 'random' to generate one):");
            string password = Console.ReadLine();

            if (password.ToLower() == "random")
            {
                password = GenerateRandomPassword();
                Console.WriteLine($"Generated password: {password}");
            }

            Console.WriteLine("Enter additional details (url/developer):");
            string additionalDetails = Console.ReadLine();

            using (StreamWriter sw = File.AppendText(passwordManagerFile))
            {
                sw.WriteLine($"{currentUser},{passwordType},{Encrypt(typename)},{Encrypt(password)},{Encrypt(additionalDetails)},{DateTime.Now},{DateTime.Now}");
            }

            Console.WriteLine("Password added successfully!");
        }
    

        private static void SearchPasswords()
        {
            Console.WriteLine("Enter search term:");
            string searchTerm = Console.ReadLine();

            string[] lines = File.ReadAllLines(passwordManagerFile);
            foreach (var line in lines)
            {
                var parts = line.Split(',');
                if (parts.Length == 7 && parts[0] == currentUser && (Decrypt(parts[2]).Contains(searchTerm) || Decrypt(parts[3]).Contains(searchTerm)))
                {
                    string decryptedTypename = Decrypt(parts[2]);
                    string decryptedPassword = Decrypt(parts[3]);
                    string decryptedDetails = Decrypt(parts[4]);

                    Console.WriteLine($"Type: {parts[1]}, Username: {decryptedTypename}, Password: ****, Details: ****, Created: {parts[5]}, Last Updated: {parts[6]}");
                    while (true)
                    {
                        Console.WriteLine("11. Unhide");
                        Console.WriteLine("22. Hide");
                        Console.WriteLine("33. Back");

                        string echoice = Console.ReadLine();

                        switch (echoice)
                        {
                            case "11":
                                Console.WriteLine($"Type: {parts[1]}, name: {decryptedTypename}, Password: {decryptedPassword}, Details: {decryptedDetails}, Created: {parts[5]}, Last Updated: {parts[6]}");
                                break;
                            case "22":
                                Console.WriteLine($"Type: {parts[1]}, name: {decryptedTypename}, Password: ****, Details: ****, Created: {parts[5]}, Last Updated: {parts[6]}");
                                break;
                            case "33":
                                PasswordManagerOperations();
                                break;
                            default:
                                Console.WriteLine("Invalid choice. Please try again.");
                                break;
                        }
                    }
                }
            }
        }

        private static void SortPasswordsByLastUpdatedDate()
        {
            List<string> userPasswords = new List<string>();

            string[] lines = File.ReadAllLines(passwordManagerFile);
            foreach (var line in lines)
            {
                var parts = line.Split(',');
                if (parts.Length == 7 && parts[0] == currentUser)
                {
                    userPasswords.Add(line);
                }
            }

            userPasswords.Sort((x, y) => DateTime.Parse(x.Split(',')[6]).CompareTo(DateTime.Parse(y.Split(',')[6])));

            foreach (var password in userPasswords)
            {
                var parts = password.Split(',');

                string decryptedTypename = Decrypt(parts[2]);
                string decryptedPassword = Decrypt(parts[3]);
                string decryptedDetails = Decrypt(parts[4]);

                Console.WriteLine($"Type: {parts[1]}, name: {decryptedTypename}, Password: {decryptedPassword}, Details: {decryptedDetails}, Created: {parts[5]}, Last Updated: {parts[6]}");
            }
        }

        #endregion

        #region Encryption, Decryption, and Random Password Generation
     private static string Encrypt(string input) {
      try {
        string ToReturn = "";
        string publickey = "12345678";
        string secretkey = "87654321";
        byte[] secretkeyByte = {};
        secretkeyByte = System.Text.Encoding.UTF8.GetBytes(secretkey);
        byte[] publickeybyte = {};
        publickeybyte = System.Text.Encoding.UTF8.GetBytes(publickey);
        MemoryStream ms = null;
        CryptoStream cs = null;
        byte[] inputbyteArray = System.Text.Encoding.UTF8.GetBytes(input);
        using (DESCryptoServiceProvider des = new DESCryptoServiceProvider()) {
          ms = new MemoryStream();
          cs = new CryptoStream(ms, des.CreateEncryptor(publickeybyte, secretkeyByte),
                                CryptoStreamMode.Write);
          cs.Write(inputbyteArray, 0, inputbyteArray.Length);
          cs.FlushFinalBlock();
          ToReturn = Convert.ToBase64String(ms.ToArray());
        }
        return ToReturn;
      } catch (Exception ex) {
        throw new Exception(ex.Message, ex.InnerException);
      }
    }
private static string Decrypt(string input) {
      try {
        string ToReturn = "";
        string publickey = "12345678";
        string secretkey = "87654321";
        byte[] privatekeyByte = {};
        privatekeyByte = System.Text.Encoding.UTF8.GetBytes(secretkey);
        byte[] publickeybyte = {};
        publickeybyte = System.Text.Encoding.UTF8.GetBytes(publickey);
        MemoryStream ms = null;
        CryptoStream cs = null;
        byte[] inputbyteArray = new byte[input.Replace(" ", "+").Length];
        inputbyteArray = Convert.FromBase64String(input.Replace(" ", "+"));
        using (DESCryptoServiceProvider des = new DESCryptoServiceProvider()) {
          ms = new MemoryStream();
          cs = new CryptoStream(ms, des.CreateDecryptor(publickeybyte, privatekeyByte),
                                CryptoStreamMode.Write);
          cs.Write(inputbyteArray, 0, inputbyteArray.Length);
          cs.FlushFinalBlock();
          Encoding encoding = Encoding.UTF8;
          ToReturn = encoding.GetString(ms.ToArray());
        }
        return ToReturn;
      } catch (Exception ae) {
        throw new Exception(ae.Message, ae.InnerException);
      }
    }

private static void ViewShowInfo()
{
    string[] lines = File.ReadAllLines(passwordManagerFile);
    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (parts.Length == 7 && parts[0] == currentUser)
        {
            // Check if encrypted values are valid Base64 strings
            if (IsValidBase64(parts[2]) && IsValidBase64(parts[3]) && IsValidBase64(parts[4]))
            {

                string decryptedTypename = Decrypt(parts[2]);
                string decryptedPassword = Decrypt(parts[3]);
                string decryptedDetails = Decrypt(parts[4]);

                // Check if decrypted values are not empty before displaying
                if (decryptedTypename != null && decryptedPassword != null && decryptedDetails != null)
                {
                    Console.WriteLine($"Type: {parts[1]}, name: {decryptedTypename}, Password: {decryptedPassword}, Details: {decryptedDetails}, Created: {parts[5]}, Last Updated: {parts[6]}");
                
                }
                else
                {
                    Console.WriteLine("Error decrypting password. The decrypted values are empty.");
                }
            }
            else
            {
                Console.WriteLine($"Error decrypting password. Invalid Base64 string detected in the encrypted values.");
            }
        }
    }
}
private static void EditPassword()
{
    Console.WriteLine("Enter the service name you want to edit:");
    string serviceName = Console.ReadLine();

    // Find the password entry to edit
    string[] lines = File.ReadAllLines(passwordManagerFile);
    List<string> newPasswords = new List<string>();
    bool found = false;

    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (parts[0] == currentUser && (Decrypt(parts[2]).Contains(serviceName) || Decrypt(parts[3]).Contains(serviceName)))
        {
            Console.WriteLine("Enter the new password (leave empty to keep the existing password):");
            string newPassword = ReadPassword();

            if (!string.IsNullOrWhiteSpace(newPassword))
            {
                // If a new password is provided, encrypt it before storing
                parts[3] = Encrypt(newPassword);
            }

            Console.WriteLine("Enter additional details (url/developer): (leave empty to keep the existing details):");
            string newDetails = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(newDetails))
            {
                parts[4] = Encrypt(newDetails);
            }

            parts[6] = DateTime.Now.ToString(); // Update last updated date
            found = true;
        }

        newPasswords.Add(string.Join(",", parts));
    }

    if (!found)
    {
        Console.WriteLine("Password not found.");
    }
    else
    {
        File.WriteAllLines(passwordManagerFile, newPasswords);
        Console.WriteLine("Password updated successfully.");
    }
}

private static void DeletePassword()
{
    Console.WriteLine("Enter the service name you want to delete:");
    string serviceName = Console.ReadLine();

    // Find and remove the password entry
    string[] lines = File.ReadAllLines(passwordManagerFile);
    List<string> newPasswords = new List<string>();
    bool found = false;

    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (parts.Length == 7 && parts[0] == currentUser && (Decrypt(parts[2]).Contains(serviceName) || Decrypt(parts[3]).Contains(serviceName)))
        {
            found = true;
        }
        else
        {
            newPasswords.Add(line);
        }
    }

    if (!found)
    {
        Console.WriteLine("Password not found.");
    }
    else
    {
        File.WriteAllLines(passwordManagerFile, newPasswords);
        Console.WriteLine("Password deleted successfully.");
    }
}

private static void ViewPasswords()
{
    string[] lines = File.ReadAllLines(passwordManagerFile);
    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (parts.Length == 7 && parts[0] == currentUser)
        {
            // Check if encrypted values are valid Base64 strings
            if (IsValidBase64(parts[2]) && IsValidBase64(parts[3]) && IsValidBase64(parts[4]))
            {

                string decryptedTypename = Decrypt(parts[2]);
                string decryptedPassword = Decrypt(parts[3]);
                string decryptedDetails = Decrypt(parts[4]);

                // Check if decrypted values are not empty before displaying
                if (decryptedTypename != null && decryptedPassword != null && decryptedDetails != null)
                {
                      Console.WriteLine($"Type: {parts[1]}, name: {decryptedTypename}, Password: ****, Details: ****, Created: {parts[5]}, Last Updated: {parts[6]}");
                
                }
                else
                {
                    Console.WriteLine("Error decrypting password. The decrypted values are empty.");
                }
            }
            else
            {
                Console.WriteLine($"Error decrypting password. Invalid Base64 string detected in the encrypted values.");
            }
        }
    }
}

private static void AdminEnd()
{
    LoadOrCreateUsersFile();

    while (true)
    {
        Console.WriteLine("*** Admin End ***");
        Console.WriteLine("1. Login");
        Console.WriteLine("2. Register");
        Console.WriteLine("3. Return to Menu");
        Console.WriteLine("0. Exit");

        string choice = Console.ReadLine();

        switch (choice)
        {
            case "1":
                currentUser = Login();
                if (currentUser != null)
                {
                    if (currentUser == "admin")
                    {
                        AdminOperations(); // Admin login
                    }
                    else
                    {
                        Console.WriteLine($"Welcome, {currentUser}!");
                        PasswordManagerOperations();
                    }
                }
                else
                {
                    Console.WriteLine("Login failed. Please try again.");
                }
                break;
            case "2":
                Register();
                break;
            case "3":
                UserManagement();
                break;
            case "0":
                Environment.Exit(0);
                break;
            default:
                Console.WriteLine("Invalid choice. Please try again.");
                break;
        }
    }
}

private static void AdminOperations()
{
    while (true)
    {
        Console.WriteLine("1. View All Passwords");
        Console.WriteLine("2. Edit Password for a User");
        Console.WriteLine("3. Delete Password for a User");
        Console.WriteLine("4. View Decrypted Information");
        Console.WriteLine("0. Logout");

        string choice = Console.ReadLine();

        switch (choice)
        {
            case "1":
                ViewAllPasswords();
                break;
            case "2":
                EditPasswordForUser();
                break;
            case "3":
                DeletePasswordForUser();
                break;
            case "4":
                ViewDecryptedInfo();
                break;
            case "0":
                currentUser = null;
                Console.WriteLine("Logged out successfully.");
                UserManagement();
                break;
            default:
                Console.WriteLine("Invalid choice. Please try again.");
                break;
        }
    }
}

private static void ViewAllPasswords()
{
    string[] lines = File.ReadAllLines(passwordManagerFile);
    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (parts.Length == 7)
        {
            string decryptedTypename = Decrypt(parts[2]);
            string decryptedPassword = Decrypt(parts[3]);
            string decryptedDetails = Decrypt(parts[4]);

            Console.WriteLine($"User: {parts[0]}, Type: {parts[1]}, Name: {decryptedTypename}, Password: ****, Details: ****, Created: {parts[5]}, Last Updated: {parts[6]}");
        }
    }
}
private static void ViewDecryptedInfo()
{
    string[] lines = File.ReadAllLines(passwordManagerFile);
    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (parts.Length == 7)
        {
            // Check if encrypted values are valid Base64 strings
            if (IsValidBase64(parts[2]) && IsValidBase64(parts[3]) && IsValidBase64(parts[4]))
            {

                string decryptedTypename = Decrypt(parts[2]);
                string decryptedPassword = Decrypt(parts[3]);
                string decryptedDetails = Decrypt(parts[4]);

                // Check if decrypted values are not empty before displaying
                if (decryptedTypename != null && decryptedPassword != null && decryptedDetails != null)
                {
                    Console.WriteLine($"Type: {parts[1]}, name: {decryptedTypename}, Password: {decryptedPassword}, Details: {decryptedDetails}, Created: {parts[5]}, Last Updated: {parts[6]}");
                
                }
                else
                {
                    Console.WriteLine("Error decrypting password. The decrypted values are empty.");
                }
            }
            else
            {
                Console.WriteLine($"Error decrypting password. Invalid Base64 string detected in the encrypted values.");
            }
        }
    }
}

private static void EditPasswordForUser()
{
     Console.WriteLine("Enter the system name you want to edit:");
    string serviceName = Console.ReadLine();

    // Find the password entry to edit
    string[] lines = File.ReadAllLines(passwordManagerFile);
    List<string> newPasswords = new List<string>();
    bool found = false;

    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (Decrypt(parts[2]).Contains(serviceName) || Decrypt(parts[3]).Contains(serviceName))
        {
            Console.WriteLine("Enter the new password (leave empty to keep the existing password):");
            string newPassword = ReadPassword();

            if (!string.IsNullOrWhiteSpace(newPassword))
            {
                // If a new password is provided, encrypt it before storing
                parts[3] = Encrypt(newPassword);
            }

            Console.WriteLine("Enter additional details (url/developer): (leave empty to keep the existing details):");
            string newDetails = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(newDetails))
            {
                parts[4] = Encrypt(newDetails);
            }

            parts[6] = DateTime.Now.ToString(); // Update last updated date
            found = true;
        }

        newPasswords.Add(string.Join(",", parts));
    }

    if (!found)
    {
        Console.WriteLine("Password not found.");
    }
    else
    {
        File.WriteAllLines(passwordManagerFile, newPasswords);
        Console.WriteLine("Password updated successfully.");
    }
}

private static void DeletePasswordForUser()
{
    Console.WriteLine("Enter the user name you want to delete:");
    string serviceName = Console.ReadLine();

    // Find and remove the password entry
    string[] lines = File.ReadAllLines(passwordManagerFile);
    List<string> newPasswords = new List<string>();
    bool found = false;

    foreach (var line in lines)
    {
        var parts = line.Split(',');
        if (parts.Length == 7 && (Decrypt(parts[2]).Contains(serviceName) || Decrypt(parts[3]).Contains(serviceName)))
        {
            found = true;
        }
        else
        {
            newPasswords.Add(line);
        }
    }

    if (!found)
    {
        Console.WriteLine("Password not found.");
    }
    else
    {
        File.WriteAllLines(passwordManagerFile, newPasswords);
        Console.WriteLine("Password deleted successfully.");
    }
}

        private static bool IsValidBase64(string input)
        {
            try
            {
                Convert.FromBase64String(input);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        private static string GenerateRandomPassword()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
            Random random = new Random();
            return new string(Enumerable.Repeat(chars, 12)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        #endregion

        #region Hashing

        private static string GetHash(string input)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] data = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

                var sBuilder = new StringBuilder();

                for (int i = 0; i < data.Length; i++)
                {
                    sBuilder.Append(data[i].ToString("x2"));
                }

                return sBuilder.ToString();
            }
        }

        private static bool VerifyHash(string input, string hash)
        {
            var hashOfInput = GetHash(input);
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            return comparer.Compare(hashOfInput, hash) == 0;
        }

        #endregion

        #region Password Input

        public static string ReadPassword()
        {
            string password = "";
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                switch (key.Key)
                {
                    case ConsoleKey.Escape:
                        return null;
                    case ConsoleKey.Enter:
                        return password;
                    case ConsoleKey.Backspace:
                        if (password.Length > 0)
                        {
                            password = password.Substring(0, (password.Length - 1));
                            Console.Write("\b \b");
                        }
                        break;
                    default:
                        password += key.KeyChar;
                        Console.Write("*");
                        break;
                }
            }
        }

        #endregion
    }
}
