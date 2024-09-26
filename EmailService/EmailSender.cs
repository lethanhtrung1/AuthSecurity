using MimeKit;
using System.Net;
using System.Net.Mail;

namespace EmailService {
	public class EmailSender : IEmailSender {
		private readonly EmailConfiguration _emailConfig;

		public EmailSender(EmailConfiguration emailConfig) {
			_emailConfig = emailConfig;
		}

		public void SendEmail(Message message) {
			MailMessage mailMessage = new MailMessage() {
				From = new MailAddress(_emailConfig.From),
				Subject = message.Subject,
				Body = message.Content
			};

			mailMessage.To.Add(message.To);

			using var smtpClient = new SmtpClient();
			smtpClient.Host = _emailConfig.SmtpServer;
			smtpClient.Port = _emailConfig.Port;
			smtpClient.Credentials = new NetworkCredential(_emailConfig.Username, _emailConfig.Password);
			smtpClient.EnableSsl = true;
			smtpClient.Send(mailMessage);
		}
	}
}
