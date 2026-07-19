'use strict';

import * as os from 'os';
import * as child_process from 'child_process';

export class NotificationProvider {
  private enabled: boolean;

  constructor(enabled = true) {
    this.enabled = enabled;
  }

  async send(
    title: string, message: string,
    severity: 'info' | 'warning' | 'critical' = 'info'
  ): Promise<void> {
    if (!this.enabled) {
      console.log(`[NOTIFICATION] ${title}: ${message}`);
      return;
    }

    const platform = os.platform();

    try {
      if (platform === 'win32') {
        await this.windowsToast(title, message, severity);
      } else if (platform === 'linux') {
        await this.linuxNotify(title, message, severity);
      } else {
        console.log(`[${severity.toUpperCase()}] ${title}: ${message}`);
      }
    } catch {
      console.log(`[${severity.toUpperCase()}] ${title}: ${message}`);
    }
  }

  private async windowsToast(
    title: string, message: string, severity: string
  ): Promise<void> {
    const icon = severity === 'critical' ? 'Error' :
                 severity === 'warning' ? 'Warning' : 'Information';
    const psScript = `
      [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
      $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
      $textNodes = $template.GetElementsByTagName("text")
      $textNodes.Item(0).AppendChild($template.CreateTextNode('${title.replace(/'/g, "''")}')) > $null
      $textNodes.Item(1).AppendChild($template.CreateTextNode('${message.replace(/'/g, "''")}')) > $null
      $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
      [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Sentinel").Show($toast)
    `;
    child_process.execSync(
      `powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`,
      { timeout: 5000, stdio: 'ignore' }
    );
  }

  private async linuxNotify(
    title: string, message: string, severity: string
  ): Promise<void> {
    const urgency = severity === 'critical' ? 'critical' :
                    severity === 'warning' ? 'normal' : 'low';
    child_process.execSync(
      `notify-send -u ${urgency} -a Sentinel "${title}" "${message}"`,
      { timeout: 3000, stdio: 'ignore' }
    );
  }

  async sendAlert(
    behavior: string, details: string, risk: string
  ): Promise<void> {
    const title = `[${risk}] Sentinel: ${behavior}`;
    await this.send(title, details, risk === 'CRITICAL' ? 'critical' : 'warning');
  }
}
