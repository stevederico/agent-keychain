import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "Model.js" as Model

BarWidget {
  id: root
  moduleName: "io.github.stevederico.agent-keychain"

  readonly property string icon: "󰌆"
  readonly property string socketPath: "/run/agent-keychain/sock"
  // Every daemon read lands in its audit log, so fetch only when the popup
  // opens, and at most once a minute.
  readonly property int refreshGapMs: 60000

  property bool popupOpen: false
  property bool running: false
  property bool installed: true
  property var secrets: []
  property var rules: []
  property var grants: []
  property var entries: []
  property double fetchedAt: 0
  property double now: Date.now()

  readonly property var recentEntries: Model.recent(entries, 8)
  readonly property string summary: !installed ? "Not installed"
    : !running ? "Daemon not running"
    : secrets.length + (secrets.length === 1 ? " secret" : " secrets") + " · " + rules.length + (rules.length === 1 ? " rule" : " rules")
      + (grants.length ? " · " + grants.length + (grants.length === 1 ? " grant" : " grants") : "")

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function checkSocket() {
    if (!socketProc.running) socketProc.running = true
  }

  function refresh(force) {
    now = Date.now()
    if (!running) return
    if (!force && now - fetchedAt < refreshGapMs) return
    fetchedAt = now
    if (!listProc.running) listProc.running = true
    if (!rulesProc.running) rulesProc.running = true
    if (!logProc.running) logProc.running = true
    if (!grantsProc.running) grantsProc.running = true
  }

  // Revoking a grant never prompts; removing a rule asks for your password.
  function revokeGrant(pid) { runAction(["revoke", String(pid)]) }
  function removeRule(rule) { runAction(["unallow", rule.agent, rule.secret]) }

  function runAction(args) {
    if (actionProc.running) return
    actionProc.command = ["agent-keychain"].concat(args)
    actionProc.running = true
  }

  function openTerminal(args) {
    Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", "agent-keychain"].concat(args))
  }

  ShellIpc {
    target: "agent-keychain"
    function toggle(): void { root.popupOpen = !root.popupOpen }
  }

  onPopupOpenChanged: if (popupOpen) { checkSocket(); refresh(false) }

  Process {
    id: socketProc
    command: ["sh", "-c", "command -v agent-keychain >/dev/null || exit 2; test -S \"$1\"", "sh", root.socketPath]
    onExited: function(exitCode) {
      root.installed = exitCode !== 2
      var was = root.running
      root.running = exitCode === 0
      if (root.running && !was && root.popupOpen) root.refresh(true)
    }
  }

  Process {
    id: listProc
    command: ["agent-keychain", "list", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.secrets = Model.parseJson(text, [])
    }
  }

  Process {
    id: rulesProc
    command: ["agent-keychain", "rules", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.rules = Model.parseJson(text, [])
    }
  }

  Process {
    id: logProc
    command: ["agent-keychain", "log", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.entries = Model.parseJson(text, [])
    }
  }

  Process {
    id: grantsProc
    command: ["agent-keychain", "grants", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.grants = Model.parseJson(text, [])
    }
  }

  Process {
    id: actionProc
    onExited: root.refresh(true)
  }

  Timer {
    interval: 30000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.checkSocket()
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.icon
    opacity: root.running ? 1 : 0.5
    tooltipText: "Agent Keychain · " + (root.running ? "running" : root.summary)

    onPressed: function(b) {
      if (!root.bar) return
      if (b === Qt.RightButton) root.openTerminal(["log"])
      else root.popupOpen = !root.popupOpen
    }
  }

  PopupCard {
    id: popup
    anchorItem: root
    bar: root.bar
    owner: root
    open: root.popupOpen
    contentWidth: popup.fittedContentWidth(Style.space(340))
    contentHeight: popup.fittedContentHeight(column.implicitHeight)

    Column {
      id: column
      width: parent.width
      spacing: Style.space(10)

      PanelHero {
        title: "Agent Keychain"
        meta: root.summary
        foreground: root.bar.foreground
        fontFamily: root.bar.fontFamily
        iconComponent: Component {
          Text {
            text: root.icon
            color: root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.display
          }
        }
      }

      PanelSeparator { foreground: root.bar.foreground }

      PanelSectionHeader {
        visible: root.running
        text: "RECENT"
        foreground: root.bar.foreground
        fontFamily: root.bar.fontFamily
      }

      Text {
        visible: root.running && root.recentEntries.length === 0
        text: "No requests yet"
        color: Qt.darker(root.bar.foreground, 1.4)
        font.family: root.bar.fontFamily
        font.pixelSize: Style.font.bodySmall
      }

      Column {
        visible: root.running && root.recentEntries.length > 0
        width: parent.width
        spacing: Style.space(4)

        Repeater {
          model: root.recentEntries

          Item {
            required property var modelData
            width: parent.width
            height: rowText.implicitHeight

            Text {
              id: mark
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              width: Style.space(16)
              text: modelData.kind === "ok" ? "✓" : modelData.kind === "denied" ? "✕" : "!"
              color: modelData.kind === "ok" ? Color.accent : Color.urgent
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              id: rowText
              anchors.left: mark.right
              anchors.right: when.left
              anchors.rightMargin: Style.space(8)
              anchors.verticalCenter: parent.verticalCenter
              textFormat: Text.PlainText
              text: modelData.agent + "  " + modelData.request.toLowerCase() + (modelData.name ? " " + modelData.name : "")
              elide: Text.ElideRight
              color: root.bar.foreground
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              id: when
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              text: modelData.outcome + " · " + Model.ago(modelData.time, root.now)
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }
      }

      PanelSectionHeader {
        visible: root.running && root.secrets.length > 0
        text: "SECRETS"
        foreground: root.bar.foreground
        fontFamily: root.bar.fontFamily
      }

      Flow {
        visible: root.running && root.secrets.length > 0
        width: parent.width
        spacing: Style.space(6)

        Repeater {
          model: root.secrets

          Text {
            required property var modelData
            textFormat: Text.PlainText
            text: modelData
            color: root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
        }
      }

      PanelSectionHeader {
        visible: root.running && root.grants.length > 0
        text: "GRANTS"
        foreground: root.bar.foreground
        fontFamily: root.bar.fontFamily
      }

      Repeater {
        model: root.running ? root.grants : []

        Item {
          required property var modelData
          width: column.width
          height: Math.max(grantText.implicitHeight, grantRevoke.height)

          Text {
            id: grantText
            anchors.left: parent.left
            anchors.right: grantLeft.left
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            textFormat: Text.PlainText
            text: modelData.program + "  " + modelData.secrets.join(",")
            elide: Text.ElideRight
            color: root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Text {
            id: grantLeft
            anchors.right: grantRevoke.left
            anchors.rightMargin: Style.space(6)
            anchors.verticalCenter: parent.verticalCenter
            text: Model.left(modelData.seconds) + " left"
            color: Qt.darker(root.bar.foreground, 1.4)
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.caption
          }

          PanelActionButton {
            id: grantRevoke
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            iconText: "󰅖"
            tooltipText: "Revoke · pid " + modelData.pid
            foreground: root.bar.foreground
            hoverColor: Color.urgent
            fontFamily: root.bar.fontFamily
            fontSize: Style.font.bodySmall
            onClicked: root.revokeGrant(modelData.pid)
          }
        }
      }

      PanelSectionHeader {
        visible: root.running && root.rules.length > 0
        text: "RULES"
        foreground: root.bar.foreground
        fontFamily: root.bar.fontFamily
      }

      Repeater {
        model: root.running ? root.rules : []

        Item {
          required property var modelData
          width: column.width
          height: Math.max(ruleText.implicitHeight, ruleRemove.height)

          Text {
            id: ruleText
            anchors.left: parent.left
            anchors.right: ruleRemove.left
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            textFormat: Text.PlainText
            text: Model.ruleLabel(modelData)
            elide: Text.ElideRight
            color: modelData.effect === "deny" ? Color.urgent : root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          PanelActionButton {
            id: ruleRemove
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            iconText: "󰅖"
            tooltipText: modelData.effect === "allow" ? "Revoke (asks for your password)" : "Remove (asks for your password)"
            foreground: root.bar.foreground
            hoverColor: Color.urgent
            fontFamily: root.bar.fontFamily
            fontSize: Style.font.bodySmall
            onClicked: root.removeRule(modelData)
          }
        }
      }

      PanelSeparator { foreground: root.bar.foreground }

      Row {
        anchors.horizontalCenter: parent.horizontalCenter
        spacing: Style.space(6)

        Button {
          text: "Log"
          iconText: "󰦪"
          foreground: root.bar.foreground
          fontFamily: root.bar.fontFamily
          onClicked: { root.openTerminal(["log"]); root.popupOpen = false }
        }

        Button {
          text: "Doctor"
          iconText: "󰓙"
          foreground: root.bar.foreground
          fontFamily: root.bar.fontFamily
          onClicked: { root.openTerminal(["doctor"]); root.popupOpen = false }
        }

        Button {
          visible: root.running
          text: "Refresh"
          iconText: "󰑐"
          foreground: root.bar.foreground
          fontFamily: root.bar.fontFamily
          onClicked: root.refresh(true)
        }
      }
    }
  }
}
