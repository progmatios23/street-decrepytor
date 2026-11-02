//! Unified host: CPU / regs / dump / log / C / links — one process, x64dbg-shaped.

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::stdout;
use street_debug::{DbgCmd, Debugger};

pub fn run_debug(path: &str) -> anyhow::Result<()> {
    let dbg = Debugger::spawn(path).map_err(|e| anyhow::anyhow!(e))?;
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    let mut cmd = String::new();
    let mut tab = 0u8; // 0 cpu, 1 dump, 2 c-hint
    loop {
        let snap = dbg.snapshot();
        term.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(8),
                    Constraint::Length(8),
                    Constraint::Length(6),
                    Constraint::Length(2),
                ])
                .split(f.area());
            let title = format!(
                " STREET  pid={}  RIP={:x}  kernel={}  {}  [F7 step  F8/F9 run  F2 bp  q quit]",
                snap.pid, snap.rip, snap.kernel, snap.last_event
            );
            f.render_widget(
                Paragraph::new(title).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                chunks[0],
            );

            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
                .split(chunks[1]);

            let cpu = if tab == 0 {
                snap.cpu.join("\n")
            } else {
                hexdump(snap.dump_base, &snap.dump)
            };
            f.render_widget(
                Paragraph::new(cpu)
                    .block(Block::default().borders(Borders::ALL).title(if tab == 0 { " CPU " } else { " DUMP " }))
                    .wrap(Wrap { trim: false }),
                cols[0],
            );
            let regs = format!(
                "RAX {:016x}\nRBX {:016x}\nRCX {:016x}\nRDX {:016x}\nRSI {:016x}\nRDI {:016x}\nRBP {:016x}\nRSP {:016x}\nRIP {:016x}\nR8  {:016x}\nR9  {:016x}",
                snap.rax, snap.rbx, snap.rcx, snap.rdx, snap.rsi, snap.rdi, snap.rbp, snap.rsp, snap.rip, snap.r8, snap.r9
            );
            f.render_widget(
                Paragraph::new(regs).block(Block::default().borders(Borders::ALL).title(" REGS ")),
                cols[1],
            );

            let log = snap.log.iter().rev().take(6).cloned().rev().collect::<Vec<_>>().join("\n");
            f.render_widget(
                Paragraph::new(log).block(Block::default().borders(Borders::ALL).title(" LOG ")),
                chunks[2],
            );
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::raw("cmd> "),
                    Span::styled(&cmd, Style::default().fg(Color::Cyan)),
                ]))
                .block(Block::default().borders(Borders::ALL).title(" COMMAND  (bp 0x.. | g | t | links | classify) ")),
                chunks[3],
            );
            f.render_widget(
                Paragraph::new("one process: debugger + disasm + kernel RPM fallback + auto-links. not an x64dbg plugin."),
                chunks[4],
            );
        })?;

        if event::poll(std::time::Duration::from_millis(80))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') if cmd.is_empty() => {
                        dbg.cmd(DbgCmd::Quit);
                        break;
                    }
                    KeyCode::F(7) => dbg.cmd(DbgCmd::Step),
                    KeyCode::F(8) | KeyCode::F(9) => dbg.cmd(DbgCmd::Run),
                    KeyCode::F(2) => {
                        let rip = dbg.snapshot().rip;
                        dbg.cmd(DbgCmd::SoftBp(rip));
                    }
                    KeyCode::Tab => tab = (tab + 1) % 2,
                    KeyCode::Enter => {
                        handle_cmd(&dbg, &cmd);
                        cmd.clear();
                    }
                    KeyCode::Backspace => {
                        cmd.pop();
                    }
                    KeyCode::Char(c) => cmd.push(c),
                    KeyCode::Esc => cmd.clear(),
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn handle_cmd(dbg: &Debugger, cmd: &str) {
    let c = cmd.trim();
    if c == "g" || c == "run" {
        dbg.cmd(DbgCmd::Run);
    } else if c == "t" || c == "step" {
        dbg.cmd(DbgCmd::Step);
    } else if let Some(rest) = c.strip_prefix("bp ") {
        if let Ok(a) = parse_hex(rest) {
            dbg.cmd(DbgCmd::SoftBp(a));
        }
    }
}

fn parse_hex(s: &str) -> Result<u64, ()> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|_| ())
}

fn hexdump(base: u64, data: &[u8]) -> String {
    let mut s = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        s.push_str(&format!("{:016x}  ", base + (i * 16) as u64));
        for b in chunk {
            s.push_str(&format!("{b:02x} "));
        }
        s.push('\n');
    }
    s
}
