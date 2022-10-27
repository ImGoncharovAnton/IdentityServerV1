using IdsTemp.Options;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;

namespace IdsTemp.Extensions;

public class MailKitEmailSender: IEmailSender
{
    public MailKitEmailSender(IOptions<MailKitEmailSenderOptions> options)
    {
        Options = options.Value;
    }

    private MailKitEmailSenderOptions Options { get; set; }
    
    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        return Execute(email, subject, htmlMessage);
    }

    private Task Execute(string to, string subject, string message)
    {
        // create message
        var email = new MimeMessage();
        email.Sender = MailboxAddress.Parse(Options.Sender_EMail);
        if (!string.IsNullOrEmpty(Options.Sender_Name))
            email.Sender.Name = Options.Sender_Name;
        email.From.Add(email.Sender);
        email.To.Add(MailboxAddress.Parse(to));
        email.Subject = subject;
        email.Body = new TextPart(TextFormat.Html) { Text = message };
        
        // send email
        using (var smtp = new SmtpClient())
        {
            smtp.Connect(Options.Host_Address, Options.Host_Port, Options.Host_SecureSocketOptions);
            smtp.Authenticate(Options.Host_Username, Options.Host_Password);
            smtp.Send(email);
            smtp.Disconnect(true);
        }

        return Task.FromResult(true);
    }
}