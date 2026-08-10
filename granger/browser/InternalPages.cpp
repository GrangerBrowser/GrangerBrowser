#include "granger/browser/InternalPages.h"

#include "granger/i18n/Localization.h"
#include "granger/ui/DesignTokens.h"

#include <QFile>
#include <QHash>
#include <QPair>
#include <QUrl>
#include <QVector>

namespace granger {
namespace {
QString e(const QString &value)
{
    return value.toHtmlEscaped();
}

QString t(const char *key)
{
    return Localization::text(QString::fromLatin1(key));
}

QString s(const QString &value)
{
    return Localization::statusText(value);
}

QString messageBlock(const QString &message)
{
    return message.trimmed().isEmpty() ? QString() : QStringLiteral("<div class=\"msg\">%1</div>").arg(e(message));
}

QString infoRow(const QString &label, const QString &value, const QString &valueId = QString())
{
    const QString id = valueId.isEmpty() ? QString() : QStringLiteral(" id=\"%1\"").arg(e(valueId));
    return QStringLiteral("<div class=\"info-row\"><span>%1</span><strong%2>%3</strong></div>").arg(e(label), id, e(value));
}

QString settingRow(const QString &label, const QString &description, const QString &control)
{
    return QStringLiteral("<div class=\"setting-row\"><div><div>%1</div><div class=\"description\">%2</div></div><div class=\"control\">%3</div></div>")
        .arg(e(label), e(description), control);
}

QString chrome(const QString &title, const QString &subtitle, const QString &content)
{
    QString html = QStringLiteral(R"HTML(
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%1</title><style>
:root{color-scheme:dark;--bg:__WINDOW_BG__;--panel:__TOOLBAR_BG__;--field:__FIELD_BG__;--hover:__HOVER_BG__;--active:__ACTIVE_BG__;--line:__BORDER__;--accent:__ACCENT__;--text:__TEXT__;--muted:__SECONDARY__;--error:__ERROR__;--success:__SUCCESS__;--warning:__WARNING__}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px "Segoe UI",sans-serif;letter-spacing:0}main{max-width:980px;margin:0 auto;padding:34px 32px 64px}header{margin-bottom:26px;border-bottom:1px solid var(--line);padding-bottom:20px}h1{font-size:28px;line-height:1.2;margin:0 0 6px;font-weight:650}h2{font-size:18px;margin:0 0 10px;font-weight:600}h3{font-size:14px;margin:26px 0 8px;color:var(--muted);font-weight:600}p{color:var(--muted);line-height:1.5;margin:7px 0 14px}a{color:#a9baff}.msg{border-left:3px solid var(--accent);background:var(--panel);padding:11px 13px;margin-bottom:20px}.section{margin:0 0 32px}.info-list{border-top:1px solid var(--line)}.info-row{display:grid;grid-template-columns:minmax(150px,220px) minmax(0,1fr);gap:18px;align-items:center;border-bottom:1px solid var(--line);padding:12px 2px;min-height:46px}.info-row span{color:var(--muted)}.info-row strong{text-align:right;font-weight:500;overflow-wrap:anywhere}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}input[type=text],input[type=url],input[type=password],input[type=number],select,textarea{min-width:220px;background:var(--field);border:1px solid var(--line);border-radius:5px;color:var(--text);padding:8px 10px;font:inherit}input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:1px}button,.button{display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--line);background:var(--field);color:var(--text);border-radius:5px;padding:8px 12px;text-decoration:none;font-weight:600;cursor:pointer;min-height:34px}button:hover,.button:hover{background:var(--hover)}button.primary,.button.primary{background:var(--accent);border-color:var(--accent);color:#fff}.button.secondary{background:transparent}.button.danger{color:var(--error)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--panel);border:1px solid var(--line);border-radius:5px;padding:12px;color:var(--text)}.mono{font:13px "Cascadia Mono","Consolas",monospace}.settings-shell{display:grid;grid-template-columns:190px minmax(0,1fr);gap:30px;align-items:start}.settings-nav{position:sticky;top:20px;display:flex;flex-direction:column;gap:2px}.settings-nav a{display:block;border-radius:5px;padding:9px 10px;color:var(--muted);text-decoration:none}.settings-nav a:hover{background:var(--hover);color:var(--text)}.settings-nav a.active{background:var(--active);color:var(--text);box-shadow:inset 3px 0 var(--accent)}.setting-row{display:grid;grid-template-columns:minmax(180px,1fr) minmax(220px,320px);gap:22px;align-items:center;border-bottom:1px solid var(--line);padding:14px 0}.setting-row .description{color:var(--muted);font-size:12px;margin-top:3px;line-height:1.4}.setting-row .control{text-align:right}.setting-row .control input[type=checkbox]{width:18px;height:18px}.setting-row .control select,.setting-row .control input[type=text],.setting-row .control input[type=url]{width:100%;min-width:0}.engine-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 18px;text-align:left}.warning{border-left:3px solid var(--warning);padding:10px 12px;background:var(--panel)}.error{border-left-color:var(--error)}details{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;color:var(--muted)}.result,.download,.bookmark,.cookie,.history{border-bottom:1px solid var(--line);padding:14px 2px}.result-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.url{color:var(--success);font-size:12px;overflow-wrap:anywhere;margin:5px 0}.download-progress{height:6px;background:var(--field);border-radius:3px;overflow:hidden;margin-top:10px}.download-progress span{display:block;height:100%;background:var(--accent)}.section-copy{max-width:720px}.settings-grid{display:grid;grid-template-columns:repeat(2,minmax(180px,1fr));gap:12px 16px}.field{display:grid;gap:6px;min-width:0}.field>span{color:var(--muted);font-size:12px}.field input,.field select{width:100%;min-width:0;min-height:40px}.check-grid{display:grid;grid-template-columns:repeat(2,minmax(180px,1fr));gap:4px 18px}.check-row{display:flex;align-items:center;gap:9px;min-height:38px;color:var(--text)}.check-row input{width:18px;height:18px;accent-color:var(--accent)}.section-heading{display:flex;align-items:start;justify-content:space-between;gap:16px}.section-heading h3{margin:0}.section-heading p{margin:5px 0 12px}.log-filters{display:grid;grid-template-columns:repeat(3,minmax(120px,1fr)) minmax(150px,1.2fr) 120px auto;gap:8px;margin:12px 0}.log-filters>*{width:100%;min-width:0}.log-table-wrap{width:100%;overflow:auto;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.log-table{width:100%;min-width:760px;border-collapse:collapse}.log-table th,.log-table td{padding:10px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.log-table th{color:var(--muted);font-size:11px;font-weight:600}.log-table td{font-size:12px}.log-table details{border:0;padding:4px 0 0}.log-table code{display:block;max-width:320px;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--muted)}.log-severity{display:inline-flex;padding:2px 6px;border-radius:4px;background:var(--field)}.log-severity.warning,.log-severity.error,.log-severity.critical{color:var(--warning)}.empty{text-align:center!important;color:var(--muted);padding:28px!important}.muted{color:var(--muted)}
@media(max-width:760px){main{padding:24px 18px}.settings-shell{grid-template-columns:1fr}.settings-nav{position:static;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));margin-bottom:18px}.setting-row,.info-row,.settings-grid,.check-grid{grid-template-columns:1fr;gap:6px}.setting-row .control,.info-row strong{text-align:left}.engine-list{grid-template-columns:1fr}.log-filters{grid-template-columns:1fr}.section-heading{flex-direction:column}}
</style></head><body><main><header><h1>%1</h1><p>%2</p></header>%3</main></body></html>)HTML")
                       .arg(e(title), e(subtitle), content);
    html.replace(QStringLiteral("</style>"), QStringLiteral(R"CSS(
main{max-width:__CONTENT_MAX__;padding:36px 34px 68px}header{margin-bottom:28px}form{margin:0}h4{font-size:13px;margin:22px 0 10px;color:var(--muted);font-weight:600}
input[type=text],input[type=url],input[type=password],select,textarea{min-height:38px}button,.button{min-height:38px;padding:8px 13px}.settings-shell{grid-template-columns:210px minmax(0,1fr);gap:32px}.settings-nav a{padding:10px 12px}.setting-row{grid-template-columns:minmax(210px,1fr) minmax(250px,340px);gap:28px;padding:15px 0}.setting-row .control{display:flex;justify-content:flex-end;align-items:center;min-height:38px}
    .settings-subsection{margin-top:32px;padding-top:20px;border-top:1px solid var(--line)}.settings-subsection>h3{margin:0 0 14px;color:var(--text);font-size:16px}.field-copy{min-width:0}.field-copy strong{display:block;font-weight:600}.field-copy span{display:block;color:var(--muted);font-size:12px;line-height:1.45;margin-top:3px}.field{display:grid;gap:6px;min-width:0}.field>span{color:var(--muted);font-size:12px;line-height:1.3}.field input,.field select{width:100%;min-width:0}
    .log-filters{grid-template-columns:repeat(3,minmax(0,1fr))}.log-filters>*,.log-filters input,.log-filters select,.log-filters button,.log-filters .ds-select{width:100%;max-width:100%;min-width:0}
    select.language-select{width:auto;min-width:14ch;max-width:100%;padding-left:12px;padding-right:34px}
.profile-activation{display:grid;grid-template-columns:minmax(220px,1fr) minmax(210px,280px) auto;gap:12px;align-items:end;padding:0 0 18px;border-bottom:1px solid var(--line)}.profile-activation select{width:100%;min-width:0}.profile-management{display:grid;gap:12px}.profile-create{display:grid;grid-template-columns:minmax(180px,1fr) minmax(180px,230px) auto;gap:10px;align-items:end}.profile-secondary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.profile-inline{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:end}.profile-reset{justify-self:start}
.form-grid{display:grid;gap:12px;align-items:end}.site-rule-grid{grid-template-columns:repeat(3,minmax(160px,1fr))}.site-rule-grid .rule-target{grid-column:span 2}.permission-grid{grid-template-columns:repeat(2,minmax(190px,1fr))}.permission-grid .permission-origin{grid-column:span 2}.grid-action{justify-self:start;min-width:110px}.settings-detail{margin-top:28px;padding-top:16px}.settings-detail summary{font-size:15px;font-weight:600;color:var(--text)}
.engine-list{gap:0;border-top:1px solid var(--line)}.engine-option{display:flex;align-items:center;gap:10px;min-height:42px;padding:7px 8px;border-bottom:1px solid var(--line);color:var(--text)}.engine-option.selected{background:var(--active)}.engine-option img{width:20px;height:20px;object-fit:contain;flex:0 0 20px}.engine-option input{flex:0 0 auto}
    .cookie-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 18px;padding-bottom:16px;border-bottom:1px solid var(--line)}.cookie-filter{display:flex;align-items:center;gap:8px;flex:1 1 460px;min-width:0}.cookie-filter input{flex:1 1 auto;min-width:150px}.cookie-toolbar-actions{display:flex;align-items:center;gap:8px;flex:0 0 auto}.cookie-count{color:var(--muted);font-size:12px;margin:0 0 10px}.cookie-confirm{border-left:3px solid var(--error);background:var(--panel);padding:13px 15px;margin:0 0 18px}.cookie-confirm strong{display:block}.cookie-confirm p{margin:5px 0 12px}button.danger-fill,.button.danger-fill{background:var(--error);border-color:var(--error);color:#fff}button.danger-fill:hover,.button.danger-fill:hover{background:#c74853;border-color:#d85a65}.compact{min-height:30px;padding:5px 9px;font-size:12px}
    .cookie-table{width:100%;border-top:1px solid var(--line)}.cookie-row{display:grid;grid-template-columns:minmax(95px,1.25fr) minmax(80px,1fr) minmax(110px,1.35fr) minmax(60px,.65fr) 58px 68px 70px minmax(95px,1fr) 112px;gap:8px;align-items:center;border-bottom:1px solid var(--line);padding:10px 4px}.cookie-head{min-height:38px;padding-top:7px;padding-bottom:7px;color:var(--muted);font-size:11px;font-weight:600}.cookie-cell{min-width:0;overflow-wrap:anywhere}.cookie-value{font-family:"Cascadia Mono","Consolas",monospace;font-size:12px;color:var(--muted)}.cookie-actions{display:flex;flex-direction:column;align-items:stretch;gap:5px}.cookie-delete{min-width:0;width:100%;padding:5px 7px;font-size:11px}.cookie-empty{text-align:center;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:42px 18px}.cookie-empty strong{display:block;font-size:15px}.cookie-empty p{margin:5px 0 0}
    body{background:#111214}main{padding-top:42px}main>header{display:grid;grid-template-columns:minmax(0,1fr);gap:4px;margin-bottom:34px;padding:0 0 24px;border-bottom:1px solid #403b3d}main>header h1{font-size:34px;line-height:1.15;font-weight:680}main>header p{max-width:760px;font-size:14px}
    .analysis-progress{max-width:680px;padding:26px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}.analysis-progress progress{display:block;width:100%;height:8px;margin:18px 0 15px;border:0;border-radius:4px;overflow:hidden;background:var(--field);accent-color:var(--accent)}.analysis-summary{display:grid;grid-template-columns:126px minmax(0,1fr);gap:28px;align-items:center;margin-bottom:22px;padding:24px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.risk-score{display:grid;place-items:center;width:116px;aspect-ratio:1;border:1px solid #5a4245;border-radius:8px;background:#201d20;text-align:center}.risk-score strong{font-size:36px;line-height:1;color:#f18a91}.risk-score span{color:var(--muted);font-size:11px}.report-nav{position:sticky;top:0;z-index:4;display:flex;gap:4px;overflow-x:auto;margin:0 0 30px;padding:8px 0;border-bottom:1px solid var(--line);background:rgba(17,18,20,.96)}.report-nav a{padding:8px 11px;border-radius:6px;color:var(--muted);text-decoration:none;white-space:nowrap}.report-nav a:hover{background:var(--hover);color:var(--text)}.report-section{scroll-margin-top:62px;margin:0 0 38px;padding:0 0 30px;border-bottom:1px solid var(--line)}.report-section>h2{font-size:20px;margin-bottom:16px}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 20px}.metric{display:grid;gap:5px;min-height:86px;padding:16px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}.metric strong{font-size:24px;font-weight:680}.metric span{color:var(--muted);font-size:12px}.dns-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:0 0 18px}.dns-record{display:grid;grid-template-columns:52px minmax(0,1fr);gap:5px 12px;align-items:start;padding:12px 14px;border:1px solid var(--line);border-radius:7px;background:var(--panel)}.dns-record strong{color:#ef8990}.dns-record span{overflow-wrap:anywhere}.dns-record small{grid-column:2;color:var(--muted)}.report-detail{margin-top:12px;padding:14px 0}.report-detail summary{color:var(--text);font-weight:600}.report-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 24px;padding:0 0 18px;border-bottom:1px solid var(--line)}.report-actions>span{margin-right:auto;color:var(--success);font-weight:600}.finding-list{border-top:1px solid var(--line);margin-bottom:24px}.finding{padding:18px 2px;border-bottom:1px solid var(--line)}.finding header{display:flex;align-items:center;gap:10px;margin:0 0 7px;padding:0;border:0}.finding p{margin:6px 0}.badge{display:inline-flex;align-items:center;min-height:22px;padding:2px 7px;border:1px solid var(--line);border-radius:4px;color:var(--muted);font-size:11px;font-weight:600}.severity-high .badge{border-color:var(--error);color:#ff9da7}.severity-medium .badge{border-color:var(--warning);color:#f1c66d}.severity-low .badge{border-color:#5e8483;color:#87c5bd}.limitations ul{margin:0;padding-left:20px;color:var(--muted)}.limitations li{margin:7px 0;line-height:1.5}
    a{color:#e19aa1}.report-nav{flex-wrap:wrap;overflow-x:visible}.report-section{scroll-margin-top:104px}.analysis-identity{min-width:0}.status-badge{display:inline-flex;align-items:center;min-height:24px;margin-bottom:8px;padding:3px 8px;border:1px solid #3f735f;border-radius:4px;color:var(--success);font-size:11px;font-weight:700;text-transform:uppercase}.analysis-identity h2{margin:0 0 6px}.analysis-identity>p{margin:0 0 12px;overflow-wrap:anywhere}.context-strip{display:flex;gap:8px;flex-wrap:wrap}.context-strip span{min-width:0;padding:5px 8px;border:1px solid var(--line);border-radius:4px;color:var(--muted);font-size:11px;overflow-wrap:anywhere}.metric-grid{grid-template-columns:repeat(6,minmax(0,1fr))}.evidence-list{border-top:1px solid var(--line)}.evidence-item{display:grid;grid-template-columns:minmax(130px,1fr) minmax(130px,1fr);gap:5px 18px;padding:13px 2px;border-bottom:1px solid var(--line)}.evidence-item strong,.evidence-item span{min-width:0;overflow-wrap:anywhere}.evidence-item span{text-align:right;color:var(--muted)}.evidence-item small{grid-column:1/-1;color:var(--muted);overflow-wrap:anywhere}.redirect-list{margin:0;padding:0;border-top:1px solid var(--line);list-style:none;counter-reset:redirect}.redirect-list li{position:relative;padding:12px 2px 12px 38px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.redirect-list li::before{counter-increment:redirect;content:counter(redirect);position:absolute;left:2px;top:11px;display:grid;place-items:center;width:24px;height:24px;border:1px solid var(--line);border-radius:4px;color:var(--muted);font:11px "Segoe UI",sans-serif}.redirect-list li.empty::before{display:none}.redirect-list li.empty{padding-left:2px;color:var(--muted)}.empty-state{display:grid;justify-items:start;gap:8px;padding:30px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.empty-state-icon{display:grid;place-items:center;width:42px;height:42px;border:1px solid #5a4245;border-radius:8px;color:#ef8990;font-size:26px}.empty-state h3{margin:4px 0 0;color:var(--text);font-size:18px}.empty-state p{max-width:560px;margin:0 0 10px}.container-meta{color:var(--muted);font-size:12px}.container-actions{margin-top:2px}
    @media(max-width:900px){.metric-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:760px){.report-nav{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none}.report-nav::-webkit-scrollbar{display:none}.report-section{scroll-margin-top:62px}.evidence-item{grid-template-columns:1fr;gap:5px}.evidence-item span{text-align:left}.evidence-item small{grid-column:1}.context-strip{display:grid;grid-template-columns:1fr}.metric-grid{grid-template-columns:1fr}}
button,.button,.settings-nav a,.result,.download,.bookmark,.cookie,.history{transition:background-color 140ms ease,border-color 140ms ease,color 140ms ease,transform 140ms ease}
button:active,.button:active{transform:translateY(1px)}button:focus-visible,.button:focus-visible,.settings-nav a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
    .result:hover,.download:hover,.bookmark:hover,.cookie:hover,.history:hover{background:var(--panel)}.download-progress span{transition:width 140ms linear}
    @media(max-width:900px){.settings-shell{grid-template-columns:180px minmax(0,1fr);gap:24px}.setting-row{grid-template-columns:minmax(170px,1fr) minmax(210px,300px);gap:20px}.site-rule-grid{grid-template-columns:repeat(2,minmax(170px,1fr))}.site-rule-grid .rule-target{grid-column:span 1}.cookie-toolbar{align-items:stretch;flex-direction:column}.cookie-toolbar-actions{align-self:flex-start}.cookie-head{display:none}.cookie-row:not(.cookie-head){grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 18px;padding:14px 10px}.cookie-row:not(.cookie-head) .cookie-cell{display:grid;grid-template-columns:minmax(76px,96px) minmax(0,1fr);gap:8px;align-items:start}.cookie-row:not(.cookie-head) .cookie-cell::before{content:attr(data-label);color:var(--muted);font:11px "Segoe UI",sans-serif}.cookie-row:not(.cookie-head) .cookie-cell:last-child{display:block}.cookie-delete{width:auto}}
@media(max-width:760px){main{padding:24px 18px 56px}.settings-shell{grid-template-columns:1fr}.settings-nav{position:static;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));margin-bottom:18px}.setting-row,.info-row{grid-template-columns:1fr;gap:8px}.setting-row .control,.info-row strong{text-align:left;justify-content:flex-start}.profile-activation,.profile-create{grid-template-columns:1fr}.profile-secondary,.site-rule-grid,.permission-grid{grid-template-columns:1fr}.permission-grid .permission-origin{grid-column:span 1}.engine-list{grid-template-columns:1fr}.analysis-summary{grid-template-columns:1fr;gap:14px}.risk-score{width:96px}.metric-grid,.dns-grid{grid-template-columns:1fr}.report-actions{position:static}.report-actions>span{width:100%;margin:0 0 4px}}
    @media(max-width:460px){.settings-nav{grid-template-columns:1fr}.profile-secondary{grid-template-columns:1fr}.profile-inline{grid-template-columns:1fr}.profile-inline button{justify-self:start}.cookie-filter{align-items:stretch;flex-direction:column}.cookie-filter input{width:100%;min-width:0}.cookie-toolbar-actions{width:100%;flex-wrap:wrap}.cookie-row:not(.cookie-head){grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>)CSS"));
    html.replace(QStringLiteral("</style>"), QStringLiteral(R"CSS(
:root{
--ds-bg-app:__WINDOW_BG__;--ds-bg-sidebar:__SIDEBAR_BG__;--ds-bg-surface:__SURFACE_BG__;
--ds-bg-elevated:__POPUP_BG__;--ds-bg-control:__FIELD_BG__;--ds-bg-hover:__HOVER_BG__;
--ds-bg-active:__ACTIVE_BG__;--ds-border-subtle:__BORDER_SUBTLE__;--ds-border:__BORDER__;
--ds-focus:__FOCUS__;--ds-text:__TEXT__;--ds-text-secondary:__SECONDARY__;
--ds-text-muted:__MUTED__;--ds-accent:__ACCENT__;--ds-accent-hover:__ACCENT_HOVER__;
--ds-accent-soft:__ACCENT_SOFT__;--ds-danger:__ERROR__;--ds-warning:__WARNING__;
--ds-success:__SUCCESS__;--ds-info:__INFO__;--ds-radius-sm:__RADIUS_SM__;
--ds-radius-md:__CONTROL_RADIUS__;--ds-radius-lg:__RADIUS_LG__;
--ds-radius-popup:__POPUP_RADIUS__;--ds-control-height:__CONTROL_HEIGHT__;
   --ds-control-height-sm:__CONTROL_HEIGHT_SM__;--ds-shadow-popup:__POPUP_SHADOW__;
   --ds-scrollbar-size:__SCROLLBAR_SIZE__;--ds-scrollbar-inset:__SCROLLBAR_INSET__;
   --ds-scrollbar-thumb:__SCROLLBAR_THUMB__;--ds-scrollbar-hover:__SCROLLBAR_THUMB_HOVER__;
   --ds-scrollbar-active:__SCROLLBAR_THUMB_ACTIVE__;
--ds-fast:__HOVER_DURATION__;--ds-normal:__POPUP_DURATION__
}
html{overflow-x:hidden;scrollbar-width:thin;scrollbar-color:var(--ds-scrollbar-thumb) transparent}
body{background:var(--ds-bg-app);color:var(--ds-text);font-family:"Segoe UI Variable","Segoe UI",sans-serif;font-size:14px;line-height:1.5}
*{letter-spacing:0}
main{width:min(100%,__CONTENT_MAX__);padding:40px 38px 72px}
main>header{margin-bottom:32px;padding:0 0 24px;border-color:var(--ds-border-subtle)}
main>header h1{font-size:32px;line-height:1.18;font-weight:680}
main>header p{max-width:760px;margin-top:8px;color:var(--ds-text-secondary)}
h2{font-size:20px;line-height:1.3;font-weight:650}
h3{margin-top:30px;color:var(--ds-text);font-size:15px;font-weight:650}
p{color:var(--ds-text-secondary)}
a{color:#ef9aa1;text-underline-offset:3px}
.section{margin-bottom:36px}
.info-list{border-color:var(--ds-border-subtle)}
.info-row{min-height:50px;padding:13px 4px;border-color:var(--ds-border-subtle)}
.info-row span{color:var(--ds-text-secondary)}
.info-row strong{color:var(--ds-text);font-weight:550}
input:not([type]),input[type=text],input[type=url],input[type=password],select,textarea{
min-height:var(--ds-control-height);padding:8px 12px;border:1px solid var(--ds-border);
border-radius:var(--ds-radius-md);background:var(--ds-bg-control);color:var(--ds-text);
font:inherit;caret-color:var(--ds-accent-hover);
transition:background-color var(--ds-fast) ease,border-color var(--ds-fast) ease,box-shadow var(--ds-fast) ease
}
textarea{min-height:88px;line-height:1.45;resize:vertical}
input::placeholder,textarea::placeholder{color:var(--ds-text-muted);opacity:1}
input:hover,select:hover,textarea:hover{border-color:#4d505b;background:var(--ds-bg-surface)}
input:focus-visible,select:focus-visible,textarea:focus-visible{
outline:0;border-color:var(--ds-focus);box-shadow:0 0 0 3px rgba(237,116,125,.16)
}
input:disabled,select:disabled,textarea:disabled{cursor:not-allowed;opacity:.58}
button,.button{
display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:var(--ds-control-height);
padding:8px 14px;border:1px solid var(--ds-border);border-radius:var(--ds-radius-md);
background:var(--ds-bg-control);color:var(--ds-text);font:600 13px/1.25 "Segoe UI Variable","Segoe UI",sans-serif;
text-decoration:none;cursor:pointer;transition:background-color var(--ds-fast) ease,border-color var(--ds-fast) ease,
color var(--ds-fast) ease,box-shadow var(--ds-fast) ease,transform __PRESSED_DURATION__ ease
}
button:hover,.button:hover{border-color:#4d505b;background:var(--ds-bg-hover)}
button:active,.button:active{transform:translateY(1px);background:var(--ds-bg-active)}
button:focus-visible,.button:focus-visible{outline:2px solid var(--ds-focus);outline-offset:2px}
button:disabled,.button[aria-disabled=true]{cursor:not-allowed;opacity:.46;transform:none}
button.primary,.button.primary{border-color:var(--ds-accent);background:var(--ds-accent);color:#fff}
button.primary:hover,.button.primary:hover{border-color:var(--ds-accent-hover);background:var(--ds-accent-hover)}
button.secondary,.button.secondary{background:transparent}
button.danger,.button.danger{color:#ff9ba4}
button.danger-fill,.button.danger-fill{border-color:var(--ds-danger);background:var(--ds-danger);color:#fff}
.compact{min-height:var(--ds-control-height-sm);padding:5px 10px}
input[type=checkbox]{
appearance:none;display:inline-grid;place-content:center;width:18px;height:18px;min-width:18px;
margin:0;border:1px solid var(--ds-border);border-radius:5px;background:var(--ds-bg-control);
vertical-align:middle;cursor:pointer;transition:background-color var(--ds-fast) ease,border-color var(--ds-fast) ease,
box-shadow var(--ds-fast) ease
}
input[type=checkbox]::before{
content:"";width:9px;height:7px;background:#fff;clip-path:polygon(8% 44%,0 57%,38% 100%,100% 17%,85% 3%,37% 72%);
transform:scale(0);transform-origin:center;transition:transform var(--ds-fast) ease
}
input[type=checkbox]:checked{border-color:var(--ds-accent);background:var(--ds-accent)}
input[type=checkbox]:checked::before{transform:scale(1)}
input[type=checkbox]:focus-visible{outline:2px solid var(--ds-focus);outline-offset:2px}
input[type=checkbox]:disabled{cursor:not-allowed;opacity:.5}
.check-row{display:flex;align-items:flex-start;gap:10px;cursor:pointer}
details{padding:14px 0;border-color:var(--ds-border-subtle)}
summary{position:relative;min-height:28px;padding:3px 28px 3px 0;color:var(--ds-text);font-weight:600;list-style:none}
summary::-webkit-details-marker{display:none}
summary::after{
content:"";position:absolute;right:7px;top:9px;width:7px;height:7px;border-right:1.5px solid var(--ds-text-muted);
border-bottom:1.5px solid var(--ds-text-muted);transform:rotate(45deg);transition:transform var(--ds-normal) ease
}
details[open]>summary::after{transform:rotate(225deg);top:13px}
summary:hover{color:#fff}
summary:focus-visible{outline:2px solid var(--ds-focus);outline-offset:3px;border-radius:var(--ds-radius-sm)}
.msg,.warning,.cookie-confirm{border-radius:var(--ds-radius-sm);background:var(--ds-bg-surface)}
.msg{border:1px solid var(--ds-border);border-left:3px solid var(--ds-accent)}
.warning{border:1px solid var(--ds-border);border-left:3px solid var(--ds-warning)}
.warning.error{border-left-color:var(--ds-danger)}
.danger-confirm-form{display:grid;gap:0;max-width:100%;margin-top:14px}
.danger-form-message{min-height:40px;margin:10px 0 0;padding:9px 11px;border:1px solid var(--ds-border);border-left:3px solid var(--ds-danger);border-radius:var(--ds-radius-sm);background:var(--ds-bg-surface);color:var(--ds-text)}
.danger-form-message:empty{visibility:hidden}
.danger-phrase-input{font-family:"Cascadia Mono","Consolas",monospace}
.empty-state{justify-items:center;padding:46px 24px;text-align:center;border-color:var(--ds-border-subtle)}
.empty-state-icon{border-radius:var(--ds-radius-md);background:var(--ds-accent-soft)}
pre{border-color:var(--ds-border);border-radius:var(--ds-radius-md);background:var(--ds-bg-surface)}
.ds-page-stack{display:grid;gap:20px;min-width:0}
.ds-card,
.privacy-page>.section,.site-info-page>.section,.reports-page>.section,.reports-page>form,
.bookmark-page>.hero{
min-width:0;margin:0;overflow:hidden;border:1px solid var(--ds-border-subtle);
border-radius:var(--ds-radius-lg);background:var(--ds-bg-surface)
}
.ds-card--compact{border-radius:var(--ds-radius-md)}
.ds-card--elevated{border-color:var(--ds-border);background:var(--ds-bg-elevated);box-shadow:var(--ds-shadow-popup)}
.ds-selectable-row{
transition:background-color var(--ds-fast) ease,border-color var(--ds-fast) ease,color var(--ds-fast) ease
}
.ds-selectable-row:hover{background:var(--ds-bg-hover)}
.ds-selectable-row:focus-within{position:relative;z-index:1;box-shadow:inset 0 0 0 2px var(--ds-focus)}
.ds-card-header,
.privacy-page>.section>h2,.site-info-page>.section>h2,
.reports-page>.section>h3,.reports-page>.section>.section-heading{
margin:0;padding:15px 17px;border-bottom:1px solid var(--ds-border-subtle)
}
.ds-card-header h2,.ds-card-header h3,
.privacy-page>.section>h2,.site-info-page>.section>h2,.reports-page>.section>h3{margin:0;font-size:16px}
.ds-card-body{min-width:0;padding:17px}
.ds-card-footer{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:14px 17px;border-top:1px solid var(--ds-border-subtle);background:rgba(255,255,255,.012)}
.ds-action-bar{display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-wrap:wrap;min-width:0}
.ds-card-list{display:grid;gap:10px;min-width:0}
.ds-info-card{overflow:hidden}
.ds-info-card>.info-list,
.privacy-page>.section>.info-list,.site-info-page>.section>.info-list,
.reports-page>.section>.info-list,.analysis-page .report-section>.info-list{
margin:0;border:0;background:transparent
}
.ds-info-card .info-row,
.privacy-page>.section>.info-list .info-row,.site-info-page>.section>.info-list .info-row,
.reports-page>.section>.info-list .info-row,.analysis-page .report-section>.info-list .info-row{
padding-left:17px;padding-right:17px
}
.ds-info-card .info-row:first-child,
.privacy-page>.section>.info-list .info-row:first-child,.site-info-page>.section>.info-list .info-row:first-child,
.reports-page>.section>.info-list .info-row:first-child,.analysis-page .report-section>.info-list .info-row:first-child{border-top:0}
.ds-info-card .info-row:last-child,
.privacy-page>.section>.info-list .info-row:last-child,.site-info-page>.section>.info-list .info-row:last-child,
.reports-page>.section>.info-list .info-row:last-child,.analysis-page .report-section>.info-list .info-row:last-child{border-bottom:0}
.ds-empty-card{display:grid;justify-items:center;gap:7px;min-height:150px;padding:38px 24px;text-align:center}
.ds-empty-card p{max-width:560px;margin:0}
.ds-disclosure-card{padding:0}
.ds-disclosure-card>summary{min-height:48px;padding:13px 44px 13px 17px}
.ds-disclosure-card>summary::after{right:19px;top:18px}
.ds-disclosure-card[open]>summary{border-bottom:1px solid var(--ds-border-subtle)}
.ds-disclosure-card[open]>summary::after{top:21px}
.ds-disclosure-card>pre,.ds-disclosure-card>.info-list{margin:16px;border:0;background:var(--ds-bg-control)}
.ds-disclosure-card>.info-list{overflow:hidden;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-md)}
.status-page .ds-action-bar{justify-content:flex-start}
.bridge-page .bridge-add-form .row{align-items:stretch}
.bridge-page .bridge-add-form input{flex:1 1 440px;min-width:180px}
.bridge-page .bridge-saved{margin:4px 0 0}
.bridge-page .bridge-saved>h2{margin:0 0 12px;font-size:17px}
.bridge-page .result,.downloads-page .result,.results-page>.result{
min-width:0;margin:0;padding:16px;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-md);
background:var(--ds-bg-surface)
}
.bridge-page .result:hover,.downloads-page .result:hover,.results-page>.result:hover{border-color:var(--ds-border);background:var(--ds-bg-hover)}
.bridge-page .result>strong,.downloads-page .result>strong{display:block;font-size:14px;font-weight:650}
.bridge-page .result pre{margin:13px 0 0}
.downloads-page .download-progress{margin:13px 0 0;background:var(--ds-bg-control)}
.bookmark-page>.hero{padding:17px}
.bookmark-page>.hero>h2{margin:-17px -17px 16px;padding:15px 17px;border-bottom:1px solid var(--ds-border-subtle);font-size:16px}
.bookmark-page .row{align-items:stretch}
.bookmark-page .row input{flex:1 1 180px;min-width:160px}
.bookmark-page #bookmark-list{margin:0 -17px;border-top:1px solid var(--ds-border-subtle);border-bottom:1px solid var(--ds-border-subtle)}
.bookmark-page #bookmark-list:empty{display:none}
.bookmark-page .bookmark-row{
margin:0;padding:14px 17px;border:0;border-bottom:1px solid var(--ds-border-subtle);border-radius:0;background:transparent
}
.bookmark-page .bookmark-row:last-child{border-bottom:0}
.bookmark-page .bookmark-row:hover{background:var(--ds-bg-hover)}
.bookmark-page .bookmark-row[draggable=true]{cursor:grab}
.bookmark-page .bookmark-row[draggable=true]:active{cursor:grabbing}
.bookmark-page #bookmark-list+.row{justify-content:flex-end;margin-top:15px}
.privacy-page>.section,.site-info-page>.section,.reports-page>.section{margin:0;padding:0}
.site-info-page>.section>p{margin:0;padding:14px 17px}
.site-info-page>.section>p+p{padding-top:0}
.site-info-page>.section>.info-list+.setting-row,.site-info-page>.section>.info-list+.row{border-top:1px solid var(--ds-border-subtle)}
.reports-page>form{padding:17px}
.reports-page>form>h3:first-of-type{margin-top:22px}
.reports-page>.section>.section-heading h3{margin:0}
.reports-page>.section>.section-heading p{margin:5px 0 0}
.reports-page>.section>.log-filters{margin:0;padding:16px 17px;border-bottom:1px solid var(--ds-border-subtle)}
.reports-page>.section>.log-table-wrap{border:0}
.reports-page>.section>.row{margin:0;padding:14px 17px;border-top:1px solid var(--ds-border-subtle)}
.reports-page>.section>p.muted{margin:0;padding:0 17px 16px}
.reports-page>.section>.info-list+.row{border-top:1px solid var(--ds-border-subtle)}
.reports-page>.section>.info-list+.row+p.muted{padding-top:14px}
.analysis-page .metric,.analysis-page .dns-record{border-color:var(--ds-border-subtle);border-radius:var(--ds-radius-md);background:var(--ds-bg-surface)}
.analysis-page .metric{transition:background-color var(--ds-fast) ease,border-color var(--ds-fast) ease}
.analysis-page .metric:hover{border-color:var(--ds-border);background:var(--ds-bg-hover)}
.analysis-page .report-section>.info-list,
.analysis-page .evidence-list,.analysis-page .redirect-list,.analysis-page .finding-list{
overflow:hidden;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-lg);background:var(--ds-bg-surface)
}
.analysis-page .evidence-item,.analysis-page .redirect-list li,.analysis-page .finding{padding-left:16px;padding-right:16px}
.analysis-page .evidence-item:last-child,.analysis-page .redirect-list li:last-child,.analysis-page .finding:last-child{border-bottom:0}
.analysis-page .context-strip span{border-color:var(--ds-border-subtle);border-radius:var(--ds-radius-sm);background:var(--ds-bg-control)}
::-webkit-scrollbar{width:var(--ds-scrollbar-size);height:var(--ds-scrollbar-size)}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{min-height:34px;border:var(--ds-scrollbar-inset) solid transparent;border-radius:999px;background:var(--ds-scrollbar-thumb);background-clip:padding-box;transition:background-color var(--ds-fast) ease}
::-webkit-scrollbar-thumb:hover{background:var(--ds-scrollbar-hover);background-clip:padding-box}
::-webkit-scrollbar-thumb:active,html[data-scroll-active=true]::-webkit-scrollbar-thumb,html[data-scroll-active=true] *::-webkit-scrollbar-thumb{background:var(--ds-scrollbar-active);background-clip:padding-box}
::-webkit-scrollbar-button{display:none;width:0;height:0}
::-webkit-scrollbar-corner{background:transparent}
@media(max-width:760px){main{padding:26px 20px 56px}main>header h1{font-size:28px}.ds-page-stack{gap:16px}.ds-card-footer{align-items:stretch;flex-direction:column}.ds-card-footer .button,.ds-card-footer button{width:100%}.reports-page>form{padding:15px}.bookmark-page>.hero{padding:15px}.bookmark-page>.hero>h2{margin:-15px -15px 14px;padding:14px 15px}.bookmark-page #bookmark-list{margin-left:-15px;margin-right:-15px}.bookmark-page .bookmark-row{padding-left:15px;padding-right:15px}}
@media(prefers-reduced-motion:reduce){
button,.button,input,select,textarea,input[type=checkbox],input[type=checkbox]::before,summary::after,::-webkit-scrollbar-thumb,.ds-selectable-row,.analysis-page .metric{transition:none!important}
}
</style>)CSS"));
    html.replace(QStringLiteral("</body>"), QStringLiteral(R"HTML(
<script>
(()=>{
    'use strict';
    const root=document.documentElement;
    let idleTimer=0;
    const markActive=()=>{
        root.dataset.scrollActive='true';
        if(idleTimer)clearTimeout(idleTimer);
        idleTimer=setTimeout(()=>{root.dataset.scrollActive='false'},__SCROLLBAR_IDLE_DELAY_MS__);
    };
    root.dataset.scrollActive='false';
    addEventListener('scroll',markActive,{capture:true,passive:true});
})();
</script></body>)HTML"));
    return DesignTokens::apply(html);
}

QString settingsPage(QString html)
{
    html.replace(QStringLiteral("<html>"), QStringLiteral("<html class=\"settings-page\">"));
    html.replace(QStringLiteral("<body>"), QStringLiteral("<body class=\"settings-page\">"));
    html.replace(QStringLiteral("</style>"), QStringLiteral(R"CSS(
.settings-page{--radius-small:__CONTROL_RADIUS__;--radius-medium:__POPUP_RADIUS__;--control-height:__CONTROL_HEIGHT__;--space-xs:__SPACING_XS__;--space-sm:__SPACING_SM__;--space-md:__SPACING_MD__;--space-lg:__SPACING_LG__;--transition-fast:__HOVER_DURATION__;--transition-popup:__POPUP_DURATION__;--scrollbar-size:__SCROLLBAR_SIZE__}
html.settings-page{overflow-x:clip;overflow-anchor:none;scrollbar-gutter:stable;scrollbar-color:var(--ds-scrollbar-thumb) transparent;scrollbar-width:thin}body.settings-page{overflow-x:clip;overflow-anchor:none}.settings-page *{scrollbar-color:var(--ds-scrollbar-thumb) transparent;scrollbar-width:thin}
.settings-page main{width:100%;min-width:0}.settings-page .settings-shell{grid-template-columns:minmax(170px,210px) minmax(0,1fr);min-width:0}.settings-page .settings-panel{min-width:0}.settings-page .settings-panel>h2{margin-bottom:18px}.settings-page .setting-row{grid-template-columns:minmax(0,1fr) minmax(230px,340px);min-width:0}.settings-page .setting-row>div:first-child{min-width:0;overflow-wrap:anywhere}.settings-page .setting-row .control{min-width:0}.settings-page input[type=text],.settings-page input[type=url],.settings-page input[type=password],.settings-page textarea{width:100%;max-width:100%;min-width:0;min-height:var(--control-height);border-radius:var(--radius-small);transition:border-color var(--transition-fast) ease,background-color var(--transition-fast) ease,box-shadow var(--transition-fast) ease}.settings-page input[type=checkbox]{width:18px;height:18px;min-width:18px;margin:0;accent-color:var(--accent);cursor:pointer}.settings-page button,.settings-page .button{min-height:var(--control-height);border-radius:var(--radius-small);white-space:normal;line-height:1.3;overflow-wrap:anywhere;transition:background-color var(--transition-fast) ease,border-color var(--transition-fast) ease,color var(--transition-fast) ease,transform __PRESSED_DURATION__ ease}.settings-page form>p:last-child:has(button,.button){display:flex;align-items:center;gap:var(--space-md);flex-wrap:wrap;margin:18px 0 0}.settings-page .row{align-items:stretch}.settings-page .row>*{max-width:100%}
.settings-page select.ds-native-select{position:absolute!important;width:1px!important;height:1px!important;min-width:0!important;min-height:0!important;margin:0!important;padding:0!important;border:0!important;opacity:0!important;pointer-events:none!important;clip:rect(0 0 0 0)!important;clip-path:inset(50%)!important;overflow:hidden!important;white-space:nowrap!important}.settings-page .ds-select{position:relative;width:100%;min-width:0;text-align:left}.settings-page .ds-select-trigger{display:grid;grid-template-columns:minmax(0,1fr) 16px;gap:10px;align-items:center;width:100%;min-width:0;min-height:var(--control-height);padding:8px 11px 8px 12px;border:1px solid var(--line);border-radius:var(--radius-small);background:var(--field);color:var(--text);font:400 14px "Segoe UI",sans-serif;text-align:left;box-shadow:none}.settings-page .ds-select-trigger:hover{border-color:#4a505b;background:var(--hover)}.settings-page .ds-select-trigger:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.settings-page .ds-select-trigger:active{transform:none;background:var(--active)}.settings-page .ds-select-trigger:disabled{cursor:not-allowed;color:#69707d;background:var(--panel);opacity:.72}.settings-page .ds-select-value{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.settings-page .ds-select-arrow{position:relative;width:14px;height:14px;justify-self:end;transition:transform var(--transition-popup) ease}.settings-page .ds-select-arrow::before{content:"";position:absolute;left:3px;top:3px;width:6px;height:6px;border-right:1.5px solid var(--muted);border-bottom:1.5px solid var(--muted);transform:rotate(45deg)}.settings-page .ds-select[data-open=true] .ds-select-arrow{transform:rotate(180deg)}.settings-page .ds-listbox{position:fixed;z-index:2147483000;display:block;max-height:__SETTINGS_SELECT_MAX_HEIGHT__;margin:0;padding:5px;overflow-x:hidden;overflow-y:auto;overscroll-behavior:contain;touch-action:pan-y;border:1px solid #454b57;border-radius:var(--radius-medium);background:#24272e;color:var(--text);box-shadow:0 10px 26px rgba(0,0,0,.34);opacity:0;visibility:hidden;pointer-events:none;transform:translateY(-3px);transition:opacity var(--transition-popup) ease,transform var(--transition-popup) ease,visibility 0s linear var(--transition-popup)}.settings-page .ds-select[data-open=true] .ds-listbox{opacity:1;visibility:visible;pointer-events:auto;transform:none;transition-delay:0s}.settings-page .ds-select[data-placement=up] .ds-listbox{transform:translateY(3px)}.settings-page .ds-select[data-placement=up][data-open=true] .ds-listbox{transform:none}.settings-page .ds-listbox.ds-measure{visibility:hidden!important;opacity:0!important;pointer-events:none!important}.settings-page .ds-option{display:flex;align-items:center;width:100%;min-height:36px;padding:8px 10px;border:1px solid transparent;border-radius:5px;color:var(--text);line-height:1.35;overflow-wrap:anywhere;cursor:pointer;user-select:none}.settings-page .ds-option:hover,.settings-page .ds-option[data-active=true]{background:var(--hover);border-color:#3d424d}.settings-page .ds-option[aria-selected=true]{background:var(--active)}.settings-page .ds-option[aria-selected=true]::after{content:"";width:6px;height:10px;margin-left:auto;border-right:2px solid #aebdff;border-bottom:2px solid #aebdff;transform:rotate(45deg);flex:0 0 6px}.settings-page .ds-option[aria-disabled=true]{color:#69707d;cursor:not-allowed;background:transparent;border-color:transparent}.settings-page .language-select-control{min-width:14ch;max-width:100%}
.settings-page .config-transfer{margin-top:28px;padding-top:16px}.settings-page .config-transfer>summary{font-size:15px;font-weight:600;color:var(--text)}.settings-page .config-transfer-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0;margin-top:16px;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.settings-page .config-transfer-group{min-width:0;padding:18px 18px 18px 0}.settings-page .config-transfer-group+ .config-transfer-group{padding-left:18px;padding-right:0;border-left:1px solid var(--line)}.settings-page .config-transfer-title{margin:0 0 12px;color:var(--text);font-size:13px;font-weight:600}.settings-page .config-transfer-actions{display:flex;align-items:stretch;gap:var(--space-md);flex-wrap:wrap}.settings-page .config-transfer-actions .button{flex:0 1 auto}.settings-page .config-export-form{display:grid;gap:14px;justify-items:start}.settings-page .check-row{display:flex;align-items:flex-start;gap:10px;min-height:var(--control-height);padding:8px 0;color:var(--text);line-height:1.45;cursor:pointer}.settings-page .check-row span{min-width:0;overflow-wrap:anywhere}.settings-page .config-preview{margin-top:14px;min-width:0;overflow-wrap:anywhere}
    .settings-page .settings-heading-actions{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--line)}.settings-page .settings-heading-actions h2{margin:0 0 6px}.settings-page .settings-heading-actions p{margin:0;max-width:620px}.settings-page .settings-heading-actions>.button{flex:0 0 auto}
    .settings-page .container-list{display:grid;gap:12px;margin-bottom:34px}.settings-page .container-item{display:grid;gap:16px;padding:18px;border:1px solid var(--line);border-radius:8px;background:rgba(29,29,32,.72)}.settings-page .container-item>header{display:flex;align-items:center;gap:12px;margin:0;padding:0 0 12px;border:0;border-bottom:1px solid var(--line)}.settings-page .container-item>header>div{display:flex;align-items:baseline;gap:10px;min-width:0;flex-wrap:wrap}.settings-page .container-item>header strong{font-size:16px}.settings-page .container-item .form-grid{grid-template-columns:minmax(170px,1.2fr) 54px minmax(150px,.8fr) minmax(200px,1.4fr) auto;gap:10px;align-items:end}.settings-page .container-item .field.wide{min-width:0}.settings-page .container-swatch{width:10px;height:30px;border-radius:5px;flex:0 0 10px}.settings-page input[type=color]{width:54px;height:40px;min-width:54px;padding:3px;border:1px solid var(--line);border-radius:var(--radius-small);background:var(--field);cursor:pointer}.settings-page .container-actions{padding-top:2px}
    .settings-page .container-visual{position:relative;display:grid;place-items:center;width:36px;height:36px;flex:0 0 36px;border:1px solid var(--line);border-radius:7px;background:var(--field)}.settings-page .container-visual img{width:20px;height:20px}.settings-page .container-visual .container-swatch{position:absolute;right:3px;bottom:3px;width:9px;height:9px;border:1px solid #202226;border-radius:50%;flex:none}
    .settings-page .ds-select-trigger:hover{border-color:#554b4e}.settings-page .ds-listbox{border-color:#4b4547;background:#262326}.settings-page .ds-option:hover,.settings-page .ds-option[data-active=true]{border-color:#4a4244}.settings-page .ds-option[aria-selected=true]::after{border-right-color:#e19aa1;border-bottom-color:#e19aa1}.settings-page .ds-select-trigger:disabled,.settings-page .ds-option[aria-disabled=true]{color:#777174}
@media(max-width:920px){.settings-page .setting-row{grid-template-columns:1fr;gap:10px;align-items:start}.settings-page .setting-row .control{justify-content:stretch;text-align:left}.settings-page .config-transfer-grid{grid-template-columns:1fr}.settings-page .config-transfer-group{padding:16px 0}.settings-page .config-transfer-group+ .config-transfer-group{padding:16px 0;border-left:0;border-top:1px solid var(--line)}.settings-page .container-item .form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.settings-page .container-item .grid-action{grid-column:1/-1}}
@media(max-width:760px){.settings-page main{padding:24px 18px 56px}.settings-page .settings-shell{grid-template-columns:1fr;gap:20px}.settings-page .settings-nav{grid-template-columns:repeat(2,minmax(0,1fr));position:static}.settings-page .profile-activation,.settings-page .profile-create,.settings-page .profile-secondary,.settings-page .profile-inline,.settings-page .site-rule-grid,.settings-page .permission-grid{grid-template-columns:1fr}.settings-page .site-rule-grid .rule-target,.settings-page .permission-grid .permission-origin{grid-column:span 1}.settings-page .config-transfer-actions{flex-direction:column;align-items:stretch}.settings-page .config-transfer-actions .button,.settings-page .config-export-form button{width:100%}.settings-page .settings-heading-actions{flex-direction:column}.settings-page .settings-heading-actions>.button{width:100%}}
@media(max-width:460px){.settings-page .settings-nav{grid-template-columns:1fr}.settings-page .setting-row{padding:13px 0}.settings-page .ds-select-value{white-space:normal}.settings-page .row{flex-direction:column}.settings-page .row>button,.settings-page .row>.button{width:100%}.settings-page .container-item .form-grid{grid-template-columns:1fr}.settings-page .container-item input[type=color]{width:100%}.settings-page .container-item{padding:14px}}
@media(prefers-reduced-motion:reduce){.settings-page .ds-select-arrow,.settings-page .ds-listbox,.settings-page button,.settings-page .button,.settings-page input{transition:none!important}}
</style>)CSS"));
    html.replace(QStringLiteral("</style>"), QStringLiteral(R"CSS(
body.settings-page{background:var(--ds-bg-app)}
.settings-page main{width:min(100%,1180px);max-width:1180px;padding:40px 36px 76px}
.settings-page main>header{margin-bottom:30px}
.settings-page main>header h1{font-size:32px}
.settings-page .settings-shell{display:grid;grid-template-columns:224px minmax(0,1fr);gap:38px;align-items:start}
.settings-page .settings-nav{
position:sticky;top:20px;display:flex;flex-direction:column;gap:18px;min-width:0;padding:4px 16px 4px 0;
border-right:1px solid var(--ds-border-subtle)
}
.settings-page .settings-nav-group{display:grid;gap:3px;min-width:0}
.settings-page .settings-nav-label{
min-height:20px;padding:0 11px;color:var(--ds-text-muted);font-size:10px;font-weight:650;line-height:20px
}
.settings-page .settings-nav a{
position:relative;display:grid;grid-template-columns:18px minmax(0,1fr);gap:10px;align-items:center;
min-height:38px;padding:8px 10px;border:1px solid transparent;
border-radius:var(--ds-radius-md);color:var(--ds-text-secondary);font-size:13px;font-weight:550;text-decoration:none;
transition:background-color var(--ds-fast) ease,color var(--ds-fast) ease,border-color var(--ds-fast) ease
}
.settings-page .settings-nav-icon{display:grid;place-items:center;width:18px;height:18px}
.settings-page .settings-nav-icon img{display:block;width:17px;height:17px;object-fit:contain;opacity:.68}
.settings-page .settings-nav-copy{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.settings-page .settings-nav a:hover{border-color:transparent;background:var(--ds-bg-hover);color:var(--ds-text)}
.settings-page .settings-nav a.active{background:var(--ds-accent-soft);color:var(--ds-text);box-shadow:none}
.settings-page .settings-nav a.active .settings-nav-icon img{opacity:1}
.settings-page .settings-nav a.active::before{
content:"";position:absolute;left:-1px;top:10px;bottom:10px;width:2px;border-radius:2px;background:var(--ds-accent-hover)
}
.settings-page .settings-panel{
--settings-content-max:860px;--settings-card-inset:18px;--settings-control-column:minmax(230px,330px);
width:100%;max-width:var(--settings-content-max);min-width:0
}
.settings-page .settings-panel>h2{margin:0 0 22px;font-size:22px}
.settings-page .settings-panel>form+h3,.settings-page .settings-panel>form+form,
.settings-page .settings-panel>details,.settings-page .settings-panel>.settings-subsection{margin-top:32px}
.settings-page .settings-panel form>h3{margin:30px 0 4px;padding-top:22px;border-top:1px solid var(--ds-border-subtle)}
.settings-page .settings-panel form>h3:first-child{margin-top:0;padding-top:0;border-top:0}
.settings-page .settings-panel>form{
min-width:0;padding:2px 18px 18px;border:1px solid var(--ds-border-subtle);border-radius:8px;
background:var(--ds-bg-surface)
}
.settings-page .settings-panel>form+form{margin-top:18px}
.settings-page .settings-panel>.settings-surface{
min-width:0;overflow:hidden;border:1px solid var(--ds-border-subtle);border-radius:8px;
background:var(--ds-bg-surface)
}
.settings-page .settings-panel>.settings-surface+.settings-surface{margin-top:18px}
.settings-page .settings-surface-header{
display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
padding:17px var(--settings-card-inset) 14px;border-bottom:1px solid var(--ds-border-subtle)
}
.settings-page .settings-surface-header h3{margin:0;color:var(--ds-text);font-size:15px}
.settings-page .settings-surface-header p{margin:4px 0 0}
.settings-page .settings-surface-body{min-width:0;padding:16px var(--settings-card-inset)}
.settings-page .settings-surface-body.flush{padding:0}
.settings-page .settings-surface-body>.info-list{border-top:0}
.settings-page .settings-surface-body.flush .info-row{padding-left:var(--settings-card-inset);padding-right:var(--settings-card-inset)}
.settings-page .settings-surface-body.flush .info-row:last-child{border-bottom:0}
.settings-page .settings-surface>form{margin:0}
.settings-page .settings-surface-footer{
display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0;
padding:15px var(--settings-card-inset);border-top:1px solid var(--ds-border-subtle);
background:rgba(255,255,255,.012)
}
.settings-page .settings-surface-footer .button,.settings-page .settings-surface-footer button{flex:0 1 auto}
.settings-page .settings-strategy-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.settings-page .settings-strategy-grid .button{width:100%;min-width:0;text-align:center}
.settings-page .settings-surface-field{display:grid;gap:7px;min-width:0}
.settings-page .settings-surface-field>span{color:var(--ds-text-secondary);font-size:12px;font-weight:550}
.settings-page .settings-surface-field>input{width:100%;min-width:0}
.settings-page .settings-panel>form>h3{
margin:0 -18px 4px;padding:17px 18px 14px;border-top:1px solid var(--ds-border-subtle);
border-bottom:1px solid var(--ds-border-subtle);color:var(--ds-text);font-size:15px
}
.settings-page .settings-panel>form>h3:first-child{border-top:0}
.settings-page .settings-panel>form>h3:not(:first-child){margin-top:16px}
.settings-page .settings-panel>form>h3+p{margin:10px 2px 13px}
.settings-page .settings-panel>form>.setting-row:first-child{border-top:0}
.settings-page .settings-panel>form>p:last-child:has(button,.button){
margin:18px -18px -18px;padding:15px 18px;border-top:1px solid var(--ds-border-subtle);
border-radius:0 0 8px 8px;background:rgba(255,255,255,.012)
}
.settings-page .settings-panel>.info-list{
overflow:hidden;border:1px solid var(--ds-border-subtle);border-radius:8px;
background:var(--ds-bg-surface)
}
.settings-page .settings-panel>.info-list .info-row{padding-left:16px;padding-right:16px}
.settings-page .setting-row{
display:grid;grid-template-columns:minmax(0,1fr) var(--settings-control-column);gap:28px;align-items:center;
min-height:66px;padding:13px 2px;border-bottom:1px solid var(--ds-border-subtle)
}
.settings-page .setting-row:first-of-type{border-top:1px solid var(--ds-border-subtle)}
.settings-page .setting-row>div:first-child>div:first-child{color:var(--ds-text);font-weight:580}
.settings-page .setting-row .description{margin-top:4px;color:var(--ds-text-muted);font-size:12px;line-height:1.45}
.settings-page .setting-row .control{display:flex;align-items:center;justify-content:flex-end;min-width:0;min-height:40px}
.settings-page .setting-row .control>input[type=checkbox]{margin-right:3px}
.settings-page .field>span{color:var(--ds-text-secondary);font-size:12px;font-weight:550}
.settings-page .check-row{min-height:40px;padding:8px 2px;color:var(--ds-text-secondary)}
.settings-page .row{gap:10px}
.settings-page form>p:last-child:has(button,.button){gap:10px;margin-top:20px}
.settings-page .ds-select-trigger{
min-height:40px;padding:8px 11px 8px 12px;border-color:var(--ds-border);border-radius:var(--ds-radius-md);
background:var(--ds-bg-control);color:var(--ds-text);font-family:"Segoe UI Variable","Segoe UI",sans-serif
}
.settings-page .ds-select-trigger:hover{border-color:#4d505b;background:var(--ds-bg-surface)}
.settings-page .ds-select-trigger:focus-visible{outline:0;border-color:var(--ds-focus);box-shadow:0 0 0 3px rgba(237,116,125,.16)}
.settings-page .ds-listbox{
padding:6px;border-color:var(--ds-border);border-radius:var(--ds-radius-popup);background:var(--ds-bg-elevated);
box-shadow:var(--ds-shadow-popup)
}
.settings-page .ds-option{min-height:38px;padding:8px 10px;border-radius:var(--ds-radius-md)}
.settings-page .ds-option:hover,.settings-page .ds-option[data-active=true]{border-color:var(--ds-border-subtle);background:var(--ds-bg-hover)}
.settings-page .ds-option[aria-selected=true]{background:var(--ds-accent-soft)}
.settings-page .ds-option[aria-selected=true]::after{border-color:var(--ds-accent-hover)}
.settings-page .settings-heading-actions{
display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin:0 0 24px;padding:0 0 22px;
border-bottom:1px solid var(--ds-border-subtle)
}
.settings-page .settings-heading-actions h2{margin:0 0 7px;font-size:22px}
.settings-page .settings-heading-actions p{max-width:610px;margin:0;color:var(--ds-text-secondary)}
.settings-page .settings-heading-actions>.button{flex:0 0 auto}
.settings-page .container-list{display:grid;gap:8px;margin:0 0 34px}
.settings-page .container-row{
position:relative;display:grid;grid-template-columns:44px minmax(0,1fr) 38px;gap:14px;align-items:center;
min-width:0;padding:13px 12px;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-md);
background:color-mix(in srgb,var(--ds-bg-surface) 82%,transparent);overflow:visible;
transition:background-color var(--ds-fast) ease,border-color var(--ds-fast) ease
}
.settings-page .container-row::before{
content:"";position:absolute;left:-1px;top:13px;bottom:13px;width:2px;border-radius:2px;background:var(--space-accent);opacity:.72
}
.settings-page .container-row:hover{border-color:var(--ds-border);background:var(--ds-bg-hover)}
.settings-page .container-row.active{
border-color:color-mix(in srgb,var(--space-accent) 54%,var(--ds-border));
background:color-mix(in srgb,var(--space-accent) 8%,var(--ds-bg-surface))
}
.settings-page .container-visual{
position:relative;display:grid;place-items:center;width:42px;height:42px;border:1px solid var(--ds-border-subtle);
border-radius:var(--ds-radius-md);background:color-mix(in srgb,var(--space-accent) 11%,var(--ds-bg-surface))
}
.settings-page .container-visual img{width:21px;height:21px;opacity:.92}
.settings-page .container-visual .container-swatch{
position:absolute;right:3px;bottom:3px;width:10px;height:10px;border:2px solid var(--ds-bg-surface);border-radius:50%
}
.settings-page .container-copy{min-width:0}
.settings-page .container-title-line{display:flex;align-items:center;gap:10px;min-width:0}
.settings-page .container-title-line strong{min-width:0;overflow:hidden;color:var(--ds-text);font-size:15px;font-weight:650;text-overflow:ellipsis;white-space:nowrap}
.settings-page .space-state{display:inline-flex;align-items:center;min-height:20px;padding:2px 6px;border:1px solid var(--ds-border-subtle);border-radius:999px;color:var(--ds-text-muted);font-size:9px;font-weight:700;line-height:1;text-transform:uppercase;white-space:nowrap}
.settings-page .space-state.default{border-color:color-mix(in srgb,var(--space-accent) 34%,var(--ds-border-subtle));color:var(--ds-text-secondary)}
.settings-page .space-state.active{border-color:color-mix(in srgb,var(--space-accent) 58%,var(--ds-border));background:color-mix(in srgb,var(--space-accent) 12%,transparent);color:var(--ds-text)}
.settings-page .container-copy>p{margin:3px 0 7px;color:var(--ds-text-secondary);font-size:12px;line-height:1.4}
.settings-page .container-badges{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.settings-page .container-badges span{
display:inline-flex;align-items:center;min-height:22px;padding:2px 7px;border:1px solid var(--ds-border-subtle);
border-radius:999px;background:rgba(255,255,255,.018);color:var(--ds-text-muted);font-size:10px;font-weight:600
}
.settings-page .container-badges .persistence{color:var(--ds-text-secondary)}
.settings-page details.container-menu{position:relative;margin:0;padding:0;border:0}
.settings-page .container-menu>summary{
display:grid;place-items:center;width:36px;height:36px;min-height:36px;padding:0;border:1px solid transparent;
border-radius:var(--ds-radius-md);color:var(--ds-text-secondary);font-size:22px;font-weight:600;line-height:1
}
.settings-page .container-menu>summary::after{display:none}
.settings-page .container-menu>summary:hover{border-color:var(--ds-border-subtle);background:var(--ds-bg-hover);color:var(--ds-text)}
.settings-page .container-menu[open]>summary{border-color:var(--ds-border);background:var(--ds-bg-active);color:var(--ds-text)}
.settings-page .container-menu-popover{
position:absolute;z-index:40;right:0;top:43px;width:252px;max-height:min(360px,calc(100vh - 24px));padding:6px;
overflow-x:hidden;overflow-y:auto;border:1px solid var(--ds-border);
border-radius:var(--ds-radius-popup);background:var(--ds-bg-elevated);box-shadow:var(--ds-shadow-popup);
transform-origin:top right;animation:dsPopupIn var(--ds-normal) ease
}
.settings-page .container-menu-popover a{
display:grid;grid-template-columns:18px minmax(0,1fr);gap:10px;align-items:center;min-height:38px;padding:8px 10px;
border:1px solid transparent;border-radius:var(--ds-radius-md);color:var(--ds-text);font-size:13px;font-weight:550;text-decoration:none
}
.settings-page .container-menu-popover a:hover,.settings-page .container-menu-popover a:focus-visible{
outline:0;border-color:var(--ds-border-subtle);background:var(--ds-bg-hover)
}
.settings-page .container-menu-popover a.destructive{color:#ff9ba4}
.settings-page .container-menu-popover a.danger-final{margin-top:2px}
.settings-page .container-menu-popover img{width:17px;height:17px;opacity:.86}
.settings-page .container-menu-popover .menu-separator{display:block;height:1px;margin:5px 6px;background:var(--ds-border-subtle)}
.settings-page .settings-detail{
margin-top:28px;padding:0;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-lg);background:var(--ds-bg-surface)
}
.settings-page .settings-detail>summary{padding:15px 48px 15px 16px}
.settings-page .settings-detail>summary::after{right:19px;top:20px}
.settings-page .settings-detail[open]>summary{border-bottom:1px solid var(--ds-border-subtle)}
.settings-page .settings-detail[open]>summary::after{top:24px}
.settings-page .settings-detail-content{padding:18px}
.settings-page .settings-detail-content>p:first-child{margin-top:0}
.settings-page .empty-state{border-color:var(--ds-border-subtle)}
.settings-page .engine-list{border-color:var(--ds-border-subtle)}
.settings-page .engine-option{min-height:46px;padding:8px 10px;border-color:var(--ds-border-subtle)}
.settings-page .engine-option.selected{background:var(--ds-accent-soft)}
@keyframes dsPopupIn{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
@media(max-width:920px){
.settings-page .settings-shell{grid-template-columns:194px minmax(0,1fr);gap:26px}
.settings-page .setting-row{grid-template-columns:1fr;gap:9px;align-items:start;padding:15px 2px}
.settings-page .setting-row .control{justify-content:flex-start;width:100%}
.settings-page .setting-row .control>.ds-select,.settings-page .setting-row .control>input{width:100%}
.settings-page .settings-strategy-grid{grid-template-columns:1fr}
}
@media(max-width:760px){
.settings-page main{padding:24px 18px 58px}
.settings-page main>header{margin-bottom:20px;padding-bottom:16px}
.settings-page main>header h1{font-size:28px}
.settings-page .settings-shell{grid-template-columns:1fr;gap:18px}
.settings-page .settings-nav{
position:static;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;min-width:0;padding:0 0 12px;
border-right:0;border-bottom:1px solid var(--ds-border-subtle)
}
.settings-page .settings-nav-group{display:contents}
.settings-page .settings-nav-label{display:none}
.settings-page .settings-nav a{grid-template-columns:16px minmax(0,1fr);min-height:36px;padding:7px 9px;font-size:12px}
.settings-page .settings-nav-icon{width:16px;height:16px}.settings-page .settings-nav-icon img{width:15px;height:15px}
.settings-page .settings-nav a.active::before{left:10px;right:10px;top:auto;bottom:-1px;width:auto;height:2px}
.settings-page .settings-heading-actions{flex-direction:column;gap:16px}
.settings-page .settings-heading-actions>.button{width:auto;max-width:100%;align-self:flex-start}
.settings-page .site-rule-grid{grid-template-columns:1fr}
.settings-page .site-rule-grid .rule-target{grid-column:1}
}
@media(max-width:480px){
.settings-page .settings-nav{grid-template-columns:1fr}
.settings-page .settings-nav a{grid-template-columns:16px auto}
.settings-page .settings-panel>form{padding-left:14px;padding-right:14px}
.settings-page .settings-panel>form>h3{margin-left:-14px;margin-right:-14px;padding-left:14px;padding-right:14px}
.settings-page .settings-panel{--settings-card-inset:14px}
.settings-page .container-row{grid-template-columns:40px minmax(0,1fr) 36px;gap:10px}
.settings-page .container-badges{gap:4px}
}
@media(prefers-reduced-motion:reduce){
.settings-page .container-menu-popover{animation:none}
.settings-page .container-row,.settings-page .settings-nav a{transition:none!important}
}
</style>)CSS"));
    html.replace(QStringLiteral("</body>"), QStringLiteral(R"HTML(
<script>
(()=>{
    'use strict';
    const nativeSelects=[...document.querySelectorAll('.settings-shell select')];
    if(!nativeSelects.length)return;
    let openControl=null;
    let typeBuffer='';
    let typeStamp=0;
    const optionNodes=control=>[...control.querySelectorAll('.ds-option')];
    const triggerFor=control=>control.querySelector('.ds-select-trigger');
    const listFor=control=>control.querySelector('.ds-listbox');
    const nativeFor=control=>control.querySelector('select');
    const enabledIndexes=control=>optionNodes(control).filter(node=>node.dataset.disabled!=='true').map(node=>Number(node.dataset.index));
    const activeIndex=control=>Number(control.dataset.active||'-1');
    const setActive=(control,index,scroll=true)=>{
        const nodes=optionNodes(control);
        if(!nodes[index]||nodes[index].dataset.disabled==='true')return;
        nodes.forEach((node,nodeIndex)=>node.dataset.active=nodeIndex===index?'true':'false');
        control.dataset.active=String(index);
        triggerFor(control).setAttribute('aria-activedescendant',nodes[index].id);
        if(scroll){
            const list=listFor(control);
            const node=nodes[index];
            const top=node.offsetTop;
            const bottom=top+node.offsetHeight;
            if(top<list.scrollTop)list.scrollTop=Math.max(0,top-5);
            else if(bottom>list.scrollTop+list.clientHeight)list.scrollTop=bottom-list.clientHeight+5;
        }
    };
    const sync=(control,index)=>{
        const select=nativeFor(control);
        const nodes=optionNodes(control);
        const selected=select.options[index];
        if(!selected||selected.disabled)return;
        select.selectedIndex=index;
        triggerFor(control).querySelector('.ds-select-value').textContent=selected.textContent;
        nodes.forEach((node,nodeIndex)=>node.setAttribute('aria-selected',nodeIndex===index?'true':'false'));
        setActive(control,index,false);
        select.dispatchEvent(new Event('input',{bubbles:true}));
        select.dispatchEvent(new Event('change',{bubbles:true}));
    };
    const layout=control=>{
        const trigger=triggerFor(control);
        const list=listFor(control);
        const rect=trigger.getBoundingClientRect();
        const margin=14;
        const viewportWidth=document.documentElement.clientWidth;
        const viewportHeight=document.documentElement.clientHeight;
        const naturalWidth=Number(control.dataset.popupWidth||rect.width);
        const width=Math.min(Math.max(rect.width,naturalWidth),Math.max(160,viewportWidth-margin*2));
        const left=Math.min(Math.max(margin,rect.left),Math.max(margin,viewportWidth-width-margin));
        list.style.width=`${Math.round(width)}px`;
        list.style.left=`${Math.round(left)}px`;
        list.style.maxHeight=`min(__SETTINGS_SELECT_MAX_HEIGHT__, ${Math.max(96,viewportHeight-margin*2)}px)`;
        const desiredHeight=Math.min(list.scrollHeight,320);
        const below=viewportHeight-rect.bottom-margin;
        const above=rect.top-margin;
        const openUp=below<Math.min(190,desiredHeight)&&above>below;
        const available=Math.max(96,(openUp?above:below)-6);
        const maxHeight=Math.min(320,available);
        list.style.maxHeight=`${Math.round(maxHeight)}px`;
        const height=Math.min(list.scrollHeight,maxHeight);
        const candidateTop=openUp?rect.top-height-6:rect.bottom+6;
        const top=Math.min(Math.max(margin,candidateTop),Math.max(margin,viewportHeight-height-margin));
        list.style.top=`${Math.floor(top)}px`;
        control.dataset.placement=openUp?'up':'down';
    };
    const close=(control,restoreFocus)=>{
        if(!control)return;
        control.dataset.open='false';
        triggerFor(control).setAttribute('aria-expanded','false');
        if(openControl===control)openControl=null;
        if(restoreFocus)triggerFor(control).focus({preventScroll:true});
    };
    const open=control=>{
        if(triggerFor(control).disabled)return;
        if(openControl&&openControl!==control)close(openControl,false);
        const list=listFor(control);
        list.classList.add('ds-measure');
        control.dataset.open='true';
        triggerFor(control).setAttribute('aria-expanded','true');
        openControl=control;
        layout(control);
        list.classList.remove('ds-measure');
        setActive(control,Math.max(0,nativeFor(control).selectedIndex));
    };
    const choose=(control,index)=>{
        sync(control,index);
        close(control,true);
    };
    const move=(control,direction)=>{
        const indexes=enabledIndexes(control);
        if(!indexes.length)return;
        const current=indexes.indexOf(activeIndex(control));
        const next=current<0?0:(current+direction+indexes.length)%indexes.length;
        setActive(control,indexes[next]);
    };
    nativeSelects.forEach((select,index)=>{
        if(select.dataset.dsEnhanced==='true')return;
        const font=getComputedStyle(select).font;
        const canvas=document.createElement('canvas');
        const metrics=canvas.getContext('2d');
        metrics.font=font;
        const naturalWidth=Math.max(...[...select.options].map(option=>metrics.measureText(option.textContent).width+52),160);
        const wrapper=document.createElement('div');
        wrapper.className=`ds-select${select.classList.contains('language-select')?' language-select-control':''}`;
        wrapper.dataset.open='false';
        wrapper.dataset.placement='down';
        wrapper.dataset.popupWidth=String(Math.ceil(naturalWidth));
        const parent=select.parentNode;
        parent.insertBefore(wrapper,select);
        wrapper.appendChild(select);
        select.classList.add('ds-native-select');
        select.dataset.dsEnhanced='true';
        select.tabIndex=-1;
        select.setAttribute('aria-hidden','true');
        const trigger=document.createElement('button');
        trigger.type='button';
        trigger.className='ds-select-trigger';
        trigger.id=`settings-combobox-${index}`;
        trigger.setAttribute('role','combobox');
        trigger.setAttribute('aria-haspopup','listbox');
        trigger.setAttribute('aria-expanded','false');
        trigger.disabled=select.disabled;
        const label=select.closest('label')?.querySelector(':scope > span')?.textContent?.trim()
            ||select.closest('.setting-row')?.querySelector(':scope > div:first-child > div:first-child')?.textContent?.trim()
            ||select.getAttribute('aria-label')||select.name;
        trigger.setAttribute('aria-label',label);
        const value=document.createElement('span');
        value.className='ds-select-value';
        const arrow=document.createElement('span');
        arrow.className='ds-select-arrow';
        arrow.setAttribute('aria-hidden','true');
        trigger.append(value,arrow);
        const list=document.createElement('div');
        list.className='ds-listbox';
        list.id=`settings-listbox-${index}`;
        list.setAttribute('role','listbox');
        list.setAttribute('aria-labelledby',trigger.id);
        trigger.setAttribute('aria-controls',list.id);
        [...select.options].forEach((option,optionIndex)=>{
            const node=document.createElement('div');
            node.className='ds-option';
            node.id=`settings-option-${index}-${optionIndex}`;
            node.dataset.index=String(optionIndex);
            node.dataset.disabled=option.disabled?'true':'false';
            node.dataset.active='false';
            node.setAttribute('role','option');
            node.setAttribute('aria-selected',optionIndex===select.selectedIndex?'true':'false');
            node.setAttribute('aria-disabled',option.disabled?'true':'false');
            node.textContent=option.textContent;
            list.appendChild(node);
        });
        wrapper.append(trigger,list);
        if(select.closest('label'))select.closest('label').dataset.dsSelectLabel='true';
        sync(wrapper,Math.max(0,select.selectedIndex));
    });
    document.addEventListener('click',event=>{
        const option=event.target.closest?.('.ds-option');
        if(option){
            event.preventDefault();
            if(option.dataset.disabled!=='true')choose(option.closest('.ds-select'),Number(option.dataset.index));
            return;
        }
        const trigger=event.target.closest?.('.ds-select-trigger');
        if(trigger){
            event.preventDefault();
            const control=trigger.closest('.ds-select');
            control.dataset.open==='true'?close(control,true):open(control);
            return;
        }
        const fieldLabel=event.target.closest?.('label[data-ds-select-label]');
        if(fieldLabel&&!event.target.closest?.('.ds-select')){
            event.preventDefault();
            const control=fieldLabel.querySelector('.ds-select');
            triggerFor(control).focus({preventScroll:true});
            open(control);
            return;
        }
        if(openControl&&!event.target.closest?.('.ds-select'))close(openControl,false);
    });
    document.addEventListener('keydown',event=>{
        const trigger=event.target.closest?.('.ds-select-trigger');
        if(!trigger)return;
        const control=trigger.closest('.ds-select');
        const isOpen=control.dataset.open==='true';
        if(event.key==='Escape'&&isOpen){event.preventDefault();event.stopPropagation();close(control,true);return;}
        if(event.key==='Tab'){if(isOpen)close(control,false);return;}
        if(event.key==='Enter'||event.key===' '){
            event.preventDefault();
            isOpen?choose(control,activeIndex(control)):open(control);
            return;
        }
        if(event.key==='ArrowDown'||event.key==='ArrowUp'){
            event.preventDefault();
            if(!isOpen)open(control);
            move(control,event.key==='ArrowDown'?1:-1);
            return;
        }
        if(event.key==='Home'||event.key==='End'){
            event.preventDefault();
            if(!isOpen)open(control);
            const indexes=enabledIndexes(control);
            if(indexes.length)setActive(control,event.key==='Home'?indexes[0]:indexes[indexes.length-1]);
            return;
        }
        if(event.key.length===1&&!event.ctrlKey&&!event.altKey&&!event.metaKey){
            const now=performance.now();
            typeBuffer=now-typeStamp>700?event.key:typeBuffer+event.key;
            typeStamp=now;
            const nodes=optionNodes(control);
            const start=Math.max(0,activeIndex(control)+1);
            const ordered=[...nodes.slice(start),...nodes.slice(0,start)];
            const match=ordered.find(node=>node.dataset.disabled!=='true'&&node.textContent.trim().toLocaleLowerCase().startsWith(typeBuffer.toLocaleLowerCase()));
            if(match){event.preventDefault();if(!isOpen)open(control);setActive(control,Number(match.dataset.index));}
        }
    });
    window.addEventListener('resize',()=>{if(openControl)layout(openControl)},{passive:true});
    document.addEventListener('scroll',event=>{
        if(!openControl)return;
        const list=listFor(openControl);
        if(event.target===list||list.contains(event.target))return;
        close(openControl,false);
    },true);
})();
</script></body>)HTML"));
    html.replace(QStringLiteral("</body>"), QStringLiteral(R"HTML(
<script>
(()=>{
    'use strict';
    const menus=[...document.querySelectorAll('details.container-menu')];
    const items=menu=>[...menu.querySelectorAll('[role="menuitem"]')];
    const close=(menu,restore=false)=>{
        if(!menu||!menu.open)return;
        menu.open=false;
        const summary=menu.querySelector(':scope>summary');
        summary?.setAttribute('aria-expanded','false');
        if(restore)summary?.focus({preventScroll:true});
    };
    menus.forEach(menu=>{
        const summary=menu.querySelector(':scope>summary');
        summary?.setAttribute('aria-haspopup','menu');
        summary?.setAttribute('aria-expanded',menu.open?'true':'false');
        menu.addEventListener('toggle',()=>{
            summary?.setAttribute('aria-expanded',menu.open?'true':'false');
            if(menu.open){
                menus.forEach(other=>{if(other!==menu)close(other,false);});
                requestAnimationFrame(()=>{
                    const popup=menu.querySelector('.container-menu-popover');
                    if(!popup)return;
                    popup.style.left='';
                    popup.style.right='0px';
                    popup.style.top='43px';
                    popup.style.bottom='auto';
                    const rect=popup.getBoundingClientRect();
                    const margin=12;
                    if(rect.left<margin){
                        popup.style.right='auto';
                        popup.style.left=`${Math.round(margin-rect.left)}px`;
                    }
                    if(rect.bottom>innerHeight-margin){
                        popup.style.top='auto';
                        popup.style.bottom='43px';
                    }
                });
            }
        });
        menu.addEventListener('keydown',event=>{
            const actionItems=items(menu);
            if(event.key==='Escape'&&menu.open){
                event.preventDefault();
                event.stopPropagation();
                close(menu,true);
                return;
            }
            if(!menu.open||!actionItems.length)return;
            const index=Math.max(0,actionItems.indexOf(document.activeElement));
            let next=-1;
            if(event.key==='ArrowDown')next=(index+1)%actionItems.length;
            else if(event.key==='ArrowUp')next=(index-1+actionItems.length)%actionItems.length;
            else if(event.key==='Home')next=0;
            else if(event.key==='End')next=actionItems.length-1;
            if(next>=0){
                event.preventDefault();
                actionItems[next].focus({preventScroll:true});
            }
        });
        summary?.addEventListener('keydown',event=>{
            if((event.key==='ArrowDown'||event.key==='Enter'||event.key===' ')&&!menu.open){
                event.preventDefault();
                menu.open=true;
                requestAnimationFrame(()=>items(menu)[0]?.focus({preventScroll:true}));
            }
        });
    });
    document.addEventListener('pointerdown',event=>{
        menus.forEach(menu=>{if(menu.open&&!menu.contains(event.target))close(menu,false);});
    });
    document.querySelectorAll('[data-open-details]').forEach(action=>{
        action.addEventListener('click',event=>{
            const target=document.getElementById(action.dataset.openDetails||'');
            if(!target)return;
            event.preventDefault();
            close(action.closest('details.container-menu'),false);
            target.open=true;
            target.scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});
            requestAnimationFrame(()=>target.querySelector(':scope>summary')?.focus({preventScroll:true}));
        });
    });
})();
</script></body>)HTML"));
    return DesignTokens::apply(html);
}

QString localImageDataUrl(const QString &resourcePath)
{
    static QHash<QString, QString> cache;
    const auto cached = cache.constFind(resourcePath);
    if (cached != cache.constEnd()) return cached.value();
    QString mimeType;
    if (resourcePath.endsWith(QStringLiteral(".png"), Qt::CaseInsensitive)) {
        mimeType = QStringLiteral("image/png");
    } else if (resourcePath.endsWith(QStringLiteral(".svg"), Qt::CaseInsensitive)) {
        mimeType = QStringLiteral("image/svg+xml");
    }
    QFile file(resourcePath);
    const QString dataUrl = !mimeType.isEmpty() && file.open(QIODevice::ReadOnly)
        ? QStringLiteral("data:%1;base64,%2")
              .arg(mimeType, QString::fromLatin1(file.readAll().toBase64()))
        : QString();
    cache.insert(resourcePath, dataUrl);
    return dataUrl;
}

QString categoryLink(const QString &id, const QString &label, const QString &active,
                     const QString &iconResource)
{
    const bool selected = id == active;
    const QString current = selected ? QStringLiteral(" aria-current=\"page\"") : QString();
    const QString iconDataUrl = localImageDataUrl(iconResource);
    const QString icon = iconDataUrl.isEmpty()
        ? QString()
        : QStringLiteral("<img src=\"%1\" alt=\"\" aria-hidden=\"true\">").arg(e(iconDataUrl));
    return QStringLiteral("<a class=\"%1\" href=\"https://granger.local/__action/settings/category?id=%2\"%3><span class=\"settings-nav-icon\">%4</span><span class=\"settings-nav-copy\">%5</span></a>")
        .arg(selected ? QStringLiteral("active") : QString(), e(id), current, icon, e(label));
}

QString settingsNavGroup(const QString &label, const QString &links)
{
    return QStringLiteral("<section class=\"settings-nav-group\" role=\"group\" aria-label=\"%1\"><div class=\"settings-nav-label\">%1</div>%2</section>")
        .arg(e(label), links);
}

QString homePage(const InternalPageContext &context, const QString &query)
{
    QString html = QStringLiteral(R"HTML(
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Granger Browser</title><style>
:root{color-scheme:dark;--bg:__WINDOW_BG__;--field:__FIELD_BG__;--line:__BORDER__;--accent:__ACCENT__;--text:__TEXT__;--muted:#d4d7de;--surface:__HOME_SURFACE__;--surface-line:__HOME_BORDER__}
*{box-sizing:border-box}html,body{width:100%;min-height:100%;overflow-x:hidden}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:"Segoe UI",sans-serif;letter-spacing:0}
body::before{content:"";position:fixed;inset:0;background-color:var(--bg);background-image:url("__HOME_WALLPAPER__");background-repeat:no-repeat;background-size:cover;background-position:50% 48%;z-index:0}
body::after{content:"";position:fixed;inset:0;background:linear-gradient(90deg,rgba(10,11,14,.24),rgba(10,11,14,.40)),rgba(10,11,14,.24);z-index:0;pointer-events:none}
.home{position:relative;z-index:1;min-height:100vh;display:grid;place-items:center;padding:48px 24px 32px}.panel{width:min(__HOME_CONTENT_MAX__,100%);text-align:center;transform:translateY(-12px);animation:home-ready 180ms ease-out}.panel-tools{display:flex;justify-content:flex-end;align-items:center;min-height:36px;margin:0 2px 9px}.ai-chat{min-width:108px;height:36px;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:0 12px 0 9px;border:1px solid rgba(198,77,105,.50);border-radius:7px;background:rgba(27,27,33,.82);color:#f4edf2;text-decoration:none;font-size:13px;font-weight:600;white-space:nowrap;box-shadow:0 7px 18px rgba(0,0,0,.20);transition:background-color 120ms ease,border-color 120ms ease,box-shadow 120ms ease,transform 80ms ease}.ai-chat img{width:21px;height:21px;object-fit:contain;flex:0 0 21px}.ai-chat:hover{background:rgba(55,29,42,.92);border-color:rgba(215,86,111,.82);box-shadow:0 8px 20px rgba(0,0,0,.26),0 0 0 1px rgba(117,76,132,.16)}.ai-chat:active{transform:translateY(1px);background:rgba(68,31,45,.94)}.ai-chat:focus-visible{outline:2px solid #f0d8df;outline-offset:3px}
.granger-title{display:inline-block;max-width:100%;overflow:visible;font-size:__HOME_TITLE_SIZE__;line-height:1.08;padding:.06em .04em .16em;margin:-.06em -.04em calc(11px - .16em);font-weight:750;letter-spacing:0;background:linear-gradient(110deg,#50363a 0%,#7c1921 23%,#dc3942 48%,#932129 72%,#59383c 100%);background-size:250% 100%;background-position:0% 50%;background-clip:text;-webkit-background-clip:text;color:transparent;-webkit-text-fill-color:transparent;-webkit-text-stroke:.4px rgba(255,214,218,.24);text-shadow:0 1px 1px rgba(255,222,225,.14),0 2px 15px rgba(0,0,0,.72);animation:granger-title-flow 6800ms ease-in-out infinite;will-change:background-position}
.subtitle{margin:0 0 24px;color:#e1e3e8;line-height:1.45;font-size:16px;text-shadow:0 1px 12px rgba(0,0,0,.45)}
form{margin:0}.searchbox{height:__SEARCH_HEIGHT__;display:flex;align-items:center;gap:10px;background:var(--surface);border:1px solid var(--surface-line);border-radius:8px;padding:8px;box-shadow:0 12px 32px rgba(0,0,0,.24);transition:border-color 120ms ease,background-color 120ms ease,box-shadow 120ms ease}
.searchbox:hover{border-color:rgba(226,231,241,.40)}.searchbox:focus-within{border-color:var(--accent);background:rgba(28,30,37,.90);box-shadow:0 0 0 2px rgba(212,85,95,.20),0 12px 32px rgba(0,0,0,.24)}
.engine{height:38px;max-width:152px;display:flex;align-items:center;gap:8px;padding:0 12px 0 7px;border-right:1px solid rgba(226,231,241,.18);color:#eceef2;font-size:13px;white-space:nowrap;flex:0 1 auto}.engine img{width:22px;height:22px;object-fit:contain;flex:0 0 22px}.engine-name{overflow:hidden;text-overflow:ellipsis}
input{flex:1;min-width:68px;height:42px;background:transparent;border:0;outline:0;color:#f7f7f8;font-size:16px;padding:8px 5px}input::placeholder{color:#b9bec8;opacity:1}
button{height:__BUTTON_HEIGHT__;flex:0 0 auto;border:1px solid #a43c45;border-radius:6px;background:#8d323a;color:white;padding:0 18px;font:600 14px "Segoe UI",sans-serif;cursor:pointer;transition:background-color 120ms ease,border-color 120ms ease,transform 80ms ease}button:hover{background:#c84650;border-color:#d4535d}button:active{transform:translateY(1px);background:#733039;border-color:#8b3740}button:focus-visible{outline:2px solid #fff;outline-offset:2px}
    .status{display:flex;align-items:center;justify-content:center;gap:9px;min-height:20px;margin-top:17px;color:#e0e2e7;font-size:12px;text-shadow:0 1px 10px rgba(0,0,0,.6)}
    .route-dot{position:relative;width:8px;height:8px;flex:0 0 8px;border-radius:50%;background:#7d8491}.route-dot::after{content:"";position:absolute;inset:-5px;border:1px solid transparent;border-radius:50%;pointer-events:none}
    .status[data-state="tor-verified"] .route-dot{background:#4fb78f}.status[data-state="tor-verified"] .route-dot::after{border-color:rgba(79,183,143,.72);animation:route-pulse 2200ms cubic-bezier(.22,.61,.36,1) infinite}
    .status[data-state="connecting"] .route-dot{background:#d4a64f;animation:route-breathe 2400ms ease-in-out infinite}.status[data-state="error"] .route-dot{background:#d98360}.status[data-state="proxy"] .route-dot{background:#9b9395}.status[data-state="direct"] .route-dot{background:#8f898b}.status[data-state="disconnected"] .route-dot{background:#777173}
.msg{text-align:left;border-left:3px solid var(--accent);padding:10px 12px;background:rgba(25,27,33,.88);margin-bottom:16px;border-radius:0 6px 6px 0}
    @keyframes home-ready{from{opacity:.72}to{opacity:1}}@keyframes granger-title-flow{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}@keyframes route-pulse{0%{opacity:.72;transform:scale(.68)}65%,100%{opacity:0;transform:scale(1.5)}}@keyframes route-breathe{0%,100%{opacity:.62;transform:scale(.82)}50%{opacity:1;transform:scale(1)}}
@media(max-width:620px){.panel-tools{margin-bottom:8px}.ai-chat{min-width:42px;width:42px;padding:0}.ai-chat-label{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}}
@media(max-width:560px){.home{padding:42px 18px 24px}.panel{transform:translateY(-5px)}.granger-title{font-size:__HOME_TITLE_COMPACT__}.subtitle{font-size:14px;margin-bottom:18px}.searchbox{gap:7px;padding:7px}.engine{max-width:112px;gap:6px;padding-left:5px;padding-right:8px}.engine img{width:20px;height:20px;flex-basis:20px}.engine-name{font-size:12px}button{padding:0 13px}}
@media(max-aspect-ratio:4/3){body::before{background-position:32% center}}
@media(max-height:520px){.home{place-items:start center;padding-top:70px;padding-bottom:20px}.panel{transform:none}.subtitle{margin-bottom:15px}.status{margin-top:11px}}
    body[data-page-hidden="true"] .granger-title{animation-play-state:paused!important}body[data-page-hidden="true"] .route-dot,body[data-page-hidden="true"] .route-dot::after,body.reduced-motion .route-dot,body.reduced-motion .route-dot::after{animation-play-state:paused!important;animation:none!important}body.reduced-motion .granger-title{animation:none!important;background-position:50% 50%}
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
    </style></head><body class="__HOME_MOTION_CLASS__"><main class="home"><section class="panel">__HOME_MESSAGE__<h1 class="granger-title">Granger Browser</h1><p class="subtitle">__HOME_SUBTITLE__</p><div class="panel-tools"><a class="ai-chat" id="home-ai-chat" href="https://granger.local/__action/ai-chat" title="__HOME_AI_TOOLTIP__" aria-label="__HOME_AI_TOOLTIP__">__HOME_AI_ICON__<span class="ai-chat-label">__HOME_AI_CHAT__</span></a></div><form action="https://granger.local/__action/search" method="get"><div class="searchbox"><span class="engine">__HOME_ENGINE_ICON__<span class="engine-name">__HOME_ENGINE_NAME__</span></span><input type="text" name="value" value="__HOME_QUERY__" placeholder="__HOME_PLACEHOLDER__" autofocus><button type="submit" name="mode" value="web">__HOME_SEARCH__</button></div></form><div class="status" id="home-network-status" data-state="__HOME_ROUTE_STATE__" title="__HOME_ROUTE_TOOLTIP__" aria-label="__HOME_ROUTE_TOOLTIP__" aria-live="polite"><span class="route-dot" aria-hidden="true"></span><span class="route-copy">__HOME_ROUTE__</span></div></section></main><script>document.addEventListener('visibilitychange',()=>{document.body.dataset.pageHidden=document.hidden?'true':'false'});document.body.dataset.pageHidden=document.hidden?'true':'false';</script></body></html>)HTML");
    const QString engineIcon = context.homeSearchEngineIconDataUrl.isEmpty()
        ? QString()
        : QStringLiteral("<img src=\"%1\" alt=\"\" aria-hidden=\"true\">")
              .arg(e(context.homeSearchEngineIconDataUrl));
    const QString aiIcon = context.homeAiIconDataUrl.isEmpty()
        ? QString()
        : QStringLiteral("<img src=\"%1\" alt=\"\" aria-hidden=\"true\">")
              .arg(e(context.homeAiIconDataUrl));
    html.replace(QStringLiteral("__HOME_WALLPAPER__"), e(context.homeBackgroundDataUrl));
    html.replace(QStringLiteral("__HOME_MESSAGE__"), messageBlock(context.message));
    html.replace(QStringLiteral("__HOME_SUBTITLE__"), e(t("home.subtitle")));
    html.replace(QStringLiteral("__HOME_ENGINE_ICON__"), engineIcon);
    html.replace(QStringLiteral("__HOME_AI_ICON__"), aiIcon);
    html.replace(QStringLiteral("__HOME_AI_CHAT__"), e(t("home.ai_chat")));
    html.replace(QStringLiteral("__HOME_AI_TOOLTIP__"), e(t("home.ai_chat_description")));
    html.replace(QStringLiteral("__HOME_ENGINE_NAME__"), e(context.defaultSearchEngineName));
    html.replace(QStringLiteral("__HOME_QUERY__"), e(query));
    html.replace(QStringLiteral("__HOME_PLACEHOLDER__"), e(t("home.search_placeholder")));
    html.replace(QStringLiteral("__HOME_SEARCH__"), e(t("common.search")));
    html.replace(QStringLiteral("__HOME_ROUTE__"), e(context.homeRouteStatus));
    html.replace(QStringLiteral("__HOME_ROUTE_STATE__"), e(context.homeRouteVisualState));
    html.replace(QStringLiteral("__HOME_ROUTE_TOOLTIP__"), e(context.homeRouteTooltip));
    html.replace(QStringLiteral("__HOME_MOTION_CLASS__"), context.reducedMotion ? QStringLiteral("reduced-motion") : QString());
    return DesignTokens::apply(html);
}
}

QString InternalPages::titleFor(const QString &address)
{
    const QString page = address.section(QLatin1Char('?'), 0, 0).toLower();
    if (page == QStringLiteral("about:settings")) return t("page.settings.title");
    if (page == QStringLiteral("about:downloads")) return t("page.downloads.title");
    if (page == QStringLiteral("about:bookmarks")) return t("page.bookmarks.title");
    if (page == QStringLiteral("about:history")) return t("page.history.title");
    if (page == QStringLiteral("about:cookies")) return t("page.cookies.title");
    if (page == QStringLiteral("about:tor")) return t("page.tor.title");
    if (page == QStringLiteral("about:bridges")) return t("page.bridges.title");
    if (page == QStringLiteral("about:privacy")) return t("page.privacy.title");
    if (page == QStringLiteral("about:site-info")) return t("page.site_info.title");
    if (page == QStringLiteral("about:site-analysis")) return t("pamp.title");
    if (page == QStringLiteral("about:granger-results")) return t("page.search_results.title");
    return QStringLiteral("Granger Browser");
}

QString InternalPages::granger(const InternalPageContext &context, const QString &query)
{
    return homePage(context, query);
}

QString InternalPages::privacy(const InternalPageContext &context)
{
    if (!context.privacyDiagnosticsHtml.isEmpty()) {
        return chrome(t("page.privacy.title"), t("page.privacy.subtitle"),
                      messageBlock(context.message)
                          + QStringLiteral("<div class=\"privacy-page ds-page-stack\">%1</div>")
                                .arg(context.privacyDiagnosticsHtml));
    }
    const QString body = messageBlock(context.message)
        + QStringLiteral("<div class=\"status-page ds-page-stack\"><section class=\"ds-card ds-info-card\"><div class=\"info-list\">%1%2%3%4%5%6</div></section></div>")
        .arg(infoRow(t("label.network_mode"), s(context.networkMode)), infoRow(t("label.current_route"), s(context.currentRoute)),
             infoRow(t("label.outbound_ip"), context.currentIp), infoRow(t("label.proxy"), s(context.proxyState)),
             infoRow(t("label.tor"), s(context.torState)), infoRow(t("label.bridge"), s(context.bridgeState)));
    return chrome(t("page.privacy.title"), t("page.privacy.subtitle"), body);
}

QString InternalPages::tor(const InternalPageContext &context)
{
    const QString body = messageBlock(context.message)
        + QStringLiteral("<div class=\"status-page ds-page-stack\"><section class=\"ds-card ds-info-card\"><div class=\"info-list\">%1%2%3%4%5</div></section><div class=\"ds-action-bar\"><a class=\"button primary\" href=\"https://granger.local/__action/settings/category?id=connection\">%6</a><a class=\"button secondary\" href=\"https://granger.local/__action/open?page=about:bridges\">%7</a></div></div>")
              .arg(infoRow(t("label.mode"), s(context.networkMode)), infoRow(t("label.route"), s(context.currentRoute)),
                   infoRow(t("label.tor"), s(context.torState)), infoRow(t("label.bridge"), s(context.bridgeState)),
                   infoRow(t("label.outbound_ip"), context.currentIp), e(t("tor.configure_connection")), e(t("tor.manage_bridges")));
    return chrome(t("page.tor.title"), t("page.tor.subtitle"), body);
}

QString InternalPages::bridges(const InternalPageContext &context)
{
    QString body = messageBlock(context.message)
        + QStringLiteral("<div class=\"bridge-page ds-page-stack\"><section class=\"ds-card ds-info-card\"><div class=\"ds-card-header\"><h2>%1</h2></div><div class=\"info-list\">%2%3%4</div></section>")
              .arg(e(t("label.status")), infoRow(t("label.bridge"), s(context.bridgeState)), infoRow(t("label.bootstrap"), s(context.bridgeBootstrap)),
                   infoRow(t("label.tor_executable"), context.torExecutable.isEmpty() ? t("status.not_detected") : context.torExecutable));
    body += QStringLiteral("<section class=\"ds-card\"><div class=\"ds-card-header\"><h2>%1</h2></div><div class=\"ds-card-body\"><form class=\"bridge-add-form\" action=\"https://granger.local/__action/bridges/save\" method=\"get\"><div class=\"row\"><input type=\"text\" name=\"line\" placeholder=\"%2\"><button type=\"submit\">%3</button><a class=\"button secondary\" href=\"https://granger.local/__action/bridges/import-qr\">%4</a><a class=\"button primary\" href=\"https://granger.local/__action/bridges/apply\">%5</a></div></form></div></section>")
                .arg(e(t("bridges.add")), e(t("bridges.paste_line")), e(t("common.save")), e(t("bridges.import_qr")), e(t("common.apply")));
    body += QStringLiteral("<section class=\"bridge-saved\"><h2>%1</h2><div class=\"ds-card-list\">%2</div></section>")
                .arg(e(t("bridges.saved")), context.bridgeProfilesHtml.isEmpty()
                    ? QStringLiteral("<div class=\"ds-card ds-empty-card\"><p>%1</p></div>").arg(e(t("bridges.none_saved")))
                    : context.bridgeProfilesHtml);
    if (!context.bridgeError.isEmpty()) body += QStringLiteral("<details class=\"ds-card ds-card--elevated ds-disclosure-card\" open><summary>%1</summary><pre>%2</pre></details>").arg(e(t("bridges.failure_reason")), e(context.bridgeError));
    if (!context.bridgeTorrcSnippet.isEmpty()) body += QStringLiteral("<details class=\"ds-card ds-disclosure-card\"><summary>%1</summary><pre>%2</pre></details>").arg(e(t("bridges.generated_torrc")), e(context.bridgeTorrcSnippet));
    body += QStringLiteral("</div>");
    return chrome(t("page.bridges.title"), t("page.bridges.subtitle"), body);
}

QString InternalPages::settings(const InternalPageContext &context)
{
    const QString category = context.settingsCategory.isEmpty() ? QStringLiteral("general") : context.settingsCategory;
    QString browserLinks;
    browserLinks += categoryLink(QStringLiteral("general"), t("settings.category.general"), category,
                                 QStringLiteral(":/icons/settings.svg"));
    browserLinks += categoryLink(QStringLiteral("search"), t("settings.category.search"), category,
                                 QStringLiteral(":/icons/search.svg"));
    browserLinks += categoryLink(QStringLiteral("downloads"), t("settings.category.downloads"), category,
                                 QStringLiteral(":/icons/downloads.svg"));
    QString privacyLinks;
    privacyLinks += categoryLink(QStringLiteral("privacy"), t("settings.category.privacy"), category,
                                 QStringLiteral(":/settings-icons/privacy-security.png"));
    privacyLinks += categoryLink(QStringLiteral("containers"), t("settings.category.containers"), category,
                                 QStringLiteral(":/settings-icons/spaces.png"));
    privacyLinks += categoryLink(QStringLiteral("isolated"), t("settings.category.isolated"), category,
                                 QStringLiteral(":/settings-icons/isolated-tabs.png"));
    privacyLinks += categoryLink(QStringLiteral("pamp"), t("settings.category.pamp"), category,
                                 QStringLiteral(":/settings-icons/pamp-lite.png"));
    QString networkLinks;
    networkLinks += categoryLink(QStringLiteral("connection"), t("settings.category.connection"), category,
                                 QStringLiteral(":/settings-icons/tor-connection.png"));
    QString systemLinks;
    systemLinks += categoryLink(QStringLiteral("reports"), t("settings.category.reports"), category,
                                QStringLiteral(":/icons/reports.svg"));
    systemLinks += categoryLink(QStringLiteral("advanced"), t("settings.category.advanced"), category,
                                QStringLiteral(":/icons/site-controls.svg"));
    systemLinks += categoryLink(QStringLiteral("danger"), t("settings.category.danger"), category,
                                QStringLiteral(":/settings-icons/danger-zone.png"));
    systemLinks += categoryLink(QStringLiteral("about"), t("settings.category.about"), category,
                                QStringLiteral(":/icons/browser.svg"));
    const QString nav = settingsNavGroup(t("settings.nav.browser"), browserLinks)
        + settingsNavGroup(t("settings.nav.privacy"), privacyLinks)
        + settingsNavGroup(t("settings.nav.network"), networkLinks)
        + settingsNavGroup(t("settings.nav.system"), systemLinks);

    QString panel;
    if (category == QStringLiteral("search")) {
        panel = QStringLiteral("<h2>%1</h2><form action=\"https://granger.local/__action/settings/search\" method=\"get\">%2%3%4<h3>%5</h3><div class=\"engine-list\">%6</div><p><button class=\"primary\" type=\"submit\">%7</button></p></form>")
                    .arg(e(t("settings.category.search")),
                         settingRow(t("settings.default_engine"), t("settings.default_engine.description"), QStringLiteral("<select name=\"defaultEngine\">%1</select>").arg(context.searchEngineOptionsHtml)),
                         settingRow(t("settings.show_engine_icon"), t("settings.show_engine_icon.description"), QStringLiteral("<input type=\"checkbox\" name=\"showIcon\" value=\"1\"%1>").arg(context.showSearchEngineIcon ? QStringLiteral(" checked") : QString())),
                         settingRow(t("settings.search_suggestions"), t("settings.search_suggestions.description"), QStringLiteral("<input type=\"checkbox\" name=\"suggestions\" value=\"1\"%1>").arg(context.searchSuggestionsEnabled ? QStringLiteral(" checked") : QString())),
                         e(t("settings.enabled_engines")), context.enabledSearchEnginesHtml, e(t("settings.save_search")));
    } else if (category == QStringLiteral("privacy")) {
        const auto check = [](const QString &name, bool enabled) {
            return QStringLiteral("<input type=\"checkbox\" name=\"%1\" value=\"1\"%2>")
                .arg(name, enabled ? QStringLiteral(" checked") : QString());
        };
        const auto lockedCheck = [](const QString &name) {
            return QStringLiteral("<input type=\"hidden\" name=\"%1\" value=\"1\"><input type=\"checkbox\" checked disabled>")
                .arg(name);
        };
        const auto ruleSelect = [](const QString &name, const QString &label) {
            return QStringLiteral("<label class=\"field\"><span>%1</span><select name=\"%2\"><option value=\"inherit\">%3</option><option value=\"allow\">%4</option><option value=\"block\">%5</option></select></label>")
                .arg(label.toHtmlEscaped(), name, t("privacy.rule.inherit").toHtmlEscaped(),
                     t("privacy.rule.allow").toHtmlEscaped(), t("privacy.rule.block").toHtmlEscaped());
        };
        const QString standardSelected = context.privacyPreset == QStringLiteral("standard") ? QStringLiteral(" selected") : QString();
        const QString balancedSelected = context.privacyPreset == QStringLiteral("balanced") ? QStringLiteral(" selected") : QString();
        const QString strictSelected = context.privacyPreset == QStringLiteral("strict") ? QStringLiteral(" selected") : QString();
        const QString preset = QStringLiteral("<select name=\"preset\"><option value=\"standard\"%1>%2</option><option value=\"balanced\"%3>%4</option><option value=\"strict\"%5>%6</option></select>")
                                   .arg(standardSelected, e(t("privacy.preset.standard")),
                                        balancedSelected, e(t("privacy.preset.balanced")),
                                        strictSelected, e(t("privacy.preset.strict")));
        const auto contentModeOption = [&context](const QString &id, const QString &label) {
            return QStringLiteral("<option value=\"%1\"%2>%3</option>")
                .arg(id, context.contentBlockingMode == id ? QStringLiteral(" selected") : QString(), e(label));
        };
        const QString contentMode = QStringLiteral("<select name=\"contentMode\">%1%2%3%4</select>")
            .arg(contentModeOption(QStringLiteral("off"), t("content_blocking.mode.off")),
                 contentModeOption(QStringLiteral("standard"), t("content_blocking.mode.standard")),
                 contentModeOption(QStringLiteral("strict"), t("content_blocking.mode.strict")),
                 contentModeOption(QStringLiteral("custom"), t("content_blocking.mode.custom")));
        const auto httpsModeOption = [&context](const QString &id, const QString &label) {
            return QStringLiteral("<option value=\"%1\"%2>%3</option>")
                .arg(id, context.httpsFirstMode == id ? QStringLiteral(" selected") : QString(), e(label));
        };
        const QString httpsMode = QStringLiteral("<select name=\"httpsMode\">%1%2%3</select>")
            .arg(httpsModeOption(QStringLiteral("off"), t("https_first.mode.off")),
                 httpsModeOption(QStringLiteral("standard"), t("https_first.mode.standard")),
                 httpsModeOption(QStringLiteral("strict"), t("https_first.mode.strict")));
        panel = QStringLiteral("<h2>%1</h2>").arg(e(t("settings.category.privacy")));
        panel += QStringLiteral("<form action=\"https://granger.local/__action/settings/privacy-security\" method=\"get\">");
        panel += QStringLiteral("<h3>%1</h3>").arg(e(t("privacy.section.protection")));
        panel += settingRow(t("privacy.protection_preset"), t("privacy.protection_preset.description"), preset);
        panel += settingRow(t("privacy.graphical_api_protection"), t("privacy.graphical_api_protection.description"), check(QStringLiteral("fingerprint"), context.fingerprintProtectionEnabled));
        panel += settingRow(t("privacy.webrtc"), t("privacy.webrtc.description"), check(QStringLiteral("webrtc"), context.webRtcLeakProtectionEnabled));
        panel += settingRow(t("privacy.trackers"), t("privacy.trackers.description"), check(QStringLiteral("trackers"), context.trackerBlockingEnabled));
        panel += settingRow(t("privacy.third_party_cookies"), t("privacy.third_party_cookies.description"), check(QStringLiteral("thirdPartyCookies"), context.privacyBlockThirdPartyCookies));
        panel += settingRow(t("privacy.referrer"), t("privacy.referrer.description"), check(QStringLiteral("referrer"), context.privacyRestrictReferrer));
        panel += settingRow(t("privacy.gpc"), t("privacy.gpc.description"), check(QStringLiteral("gpc"), context.globalPrivacyControlEnabled));
        panel += settingRow(t("privacy.dnt"), t("privacy.dnt.description"), check(QStringLiteral("dnt"), context.doNotTrackEnabled));

        panel += QStringLiteral("<h3>%1</h3><p>%2</p>")
                     .arg(e(t("privacy.script_control")), e(t("privacy.script_control.description")));
        panel += settingRow(t("privacy.javascript"), t("privacy.javascript.description"), check(QStringLiteral("javascript"), context.privacyJavascriptEnabled));
        panel += settingRow(t("privacy.third_party_scripts"), t("privacy.third_party_scripts.description"), check(QStringLiteral("thirdPartyScripts"), context.privacyBlockThirdPartyScripts));
        panel += settingRow(t("privacy.third_party_frames"), t("privacy.third_party_frames.description"), check(QStringLiteral("thirdPartyFrames"), context.privacyBlockThirdPartyFrames));
        panel += settingRow(t("privacy.webassembly"), t("privacy.webassembly.description"), check(QStringLiteral("blockWebAssembly"), context.privacyBlockWebAssembly));

        panel += QStringLiteral("<h3>%1</h3><p>%2</p>")
                     .arg(e(t("privacy.link_cleaning")), e(t("privacy.link_cleaning.description")));
        panel += settingRow(t("privacy.strip_tracking"), t("privacy.strip_tracking.description"), check(QStringLiteral("stripTracking"), context.stripTrackingParametersEnabled));
        panel += settingRow(t("privacy.redirect_protection"), t("privacy.redirect_protection.description"), check(QStringLiteral("resolveRedirects"), context.resolveTrackingRedirectsEnabled));

        panel += QStringLiteral("<h3>%1</h3><p>%2</p>")
                     .arg(e(t("tracker_protection.title")), e(t("tracker_protection.description")));
        panel += settingRow(t("content_blocking.mode"), t("content_blocking.mode.description"), contentMode);
        panel += settingRow(t("content_blocking.ads"), t("content_blocking.ads.description"), check(QStringLiteral("contentAds"), context.contentBlockAdsEnabled));
        panel += settingRow(t("content_blocking.trackers"), t("content_blocking.trackers.description"), check(QStringLiteral("contentTrackers"), context.contentBlockTrackersEnabled));
        panel += settingRow(t("content_blocking.cryptomining"), t("content_blocking.cryptomining.description"), check(QStringLiteral("contentMining"), context.contentBlockCryptominingEnabled));
        panel += settingRow(t("content_blocking.social"), t("content_blocking.social.description"), check(QStringLiteral("contentSocial"), context.contentBlockSocialEnabled));
        panel += settingRow(t("content_blocking.cosmetic"), t("content_blocking.cosmetic.description"), check(QStringLiteral("contentCosmetic"), context.contentBlockCosmeticEnabled));
        panel += settingRow(t("content_blocking.regional"), t("content_blocking.regional.description"), check(QStringLiteral("contentRegional"), context.contentBlockRegionalEnabled));
        panel += QStringLiteral("<div class=\"info-list\">%1%2%3%4%5</div>")
                     .arg(infoRow(t("content_blocking.network_rules"), QString::number(context.contentBlockingNetworkRuleCount)),
                          infoRow(t("content_blocking.cosmetic_rules"), QString::number(context.contentBlockingCosmeticRuleCount)),
                          infoRow(t("content_blocking.blocked_requests"), QString::number(context.contentBlockedRequestCount)),
                          infoRow(t("content_blocking.sources"), QString::number(context.contentBlockingSourceCount)),
                          infoRow(t("content_blocking.last_update"),
                                  context.contentBlockingUpdateInProgress
                                      ? t("content_blocking.updating")
                                      : (context.contentBlockingLastUpdate.isEmpty()
                                             ? t("content_blocking.never_updated")
                                             : context.contentBlockingLastUpdate)));
        panel += QStringLiteral("<div class=\"row\"><a class=\"button primary\" href=\"https://granger.local/__action/content-blocking/update\">%1</a><a class=\"button secondary\" href=\"https://granger.local/__action/content-blocking/reload\">%2</a><a class=\"button secondary\" href=\"https://granger.local/__action/content-blocking/import\">%3</a><a class=\"button secondary\" href=\"https://granger.local/__action/content-blocking/reset\">%4</a></div>")
                     .arg(e(t("content_blocking.update")), e(t("content_blocking.reload_local")),
                          e(t("content_blocking.import_local")), e(t("content_blocking.reset")));
        panel += QStringLiteral("<details><summary>%1</summary>%2</details>")
                     .arg(e(t("content_blocking.allowlist")), context.contentBlockingAllowlistHtml);

        panel += QStringLiteral("<h3>%1</h3><p>%2</p>")
                     .arg(e(t("https_first.title")), e(t("https_first.description")));
        panel += settingRow(t("https_first.mode"), t("https_first.mode.description"), httpsMode);
        panel += settingRow(t("https_first.block_fallback"), t("https_first.block_fallback.description"), check(QStringLiteral("httpsBlockFallback"), context.blockInsecureFallbackEnabled));
        panel += settingRow(t("https_first.warn_forms"), t("https_first.warn_forms.description"), check(QStringLiteral("httpsWarnForms"), context.warnHttpFormsEnabled));
        panel += settingRow(t("https_first.mixed_content"), t("https_first.mixed_content.description"), check(QStringLiteral("httpsMixedContent"), context.upgradeMixedContentEnabled));
        panel += settingRow(t("https_first.show_warning"), t("https_first.show_warning.description"), check(QStringLiteral("httpsShowWarning"), context.showInsecureConnectionWarningEnabled));
        panel += settingRow(t("https_first.remember_exceptions"), t("https_first.remember_exceptions.description"), check(QStringLiteral("httpsRememberExceptions"), context.rememberHttpExceptionsEnabled));
        panel += QStringLiteral("<details><summary>%1</summary>%2</details>")
                     .arg(e(t("https_first.exceptions")), context.httpsFirstExceptionsHtml);

        panel += QStringLiteral("<h3>%1</h3>").arg(e(t("privacy.section.site_data")));
        panel += settingRow(t("privacy.clear_cookies_exit"), t("privacy.clear_cookies_exit.description"), check(QStringLiteral("clearCookies"), context.clearCookiesOnExit));
        panel += settingRow(t("privacy.clear_cache_exit"), t("privacy.clear_cache_exit.description"), check(QStringLiteral("clearCache"), context.clearCacheOnExit));
        panel += settingRow(t("privacy.clear_storage_exit"), t("privacy.clear_storage_exit.description"), check(QStringLiteral("clearStorage"), context.clearStorageOnExit));

        panel += QStringLiteral("<h3>%1</h3>").arg(e(t("privacy.section.tor")));
        panel += settingRow(t("privacy.tor_isolation"), t("privacy.tor_isolation.description"), lockedCheck(QStringLiteral("torIsolation")));
        panel += settingRow(t("privacy.clear_tor_disconnect"), t("privacy.clear_tor_disconnect.description"), check(QStringLiteral("clearTor"), context.clearTorOnDisconnect));
        panel += settingRow(t("privacy.block_fallback"), t("privacy.block_fallback.description"), lockedCheck(QStringLiteral("blockFallback")));
        panel += settingRow(t("privacy.disable_webrtc_tor"), t("privacy.disable_webrtc_tor.description"), lockedCheck(QStringLiteral("disableWebRtcTor")));
        panel += settingRow(t("privacy.onion_isolation"), t("privacy.onion_isolation.description"), lockedCheck(QStringLiteral("onionIsolation")));

        panel += QStringLiteral("<details><summary>%1</summary>").arg(e(t("privacy.section.advanced")));
        panel += settingRow(t("privacy.popups"), t("privacy.popups.description"), check(QStringLiteral("blockPopups"), context.privacyBlockPopups));
        panel += settingRow(t("privacy.prefetch"), t("privacy.prefetch.description"), check(QStringLiteral("disablePrefetch"), context.privacyDisablePrefetch));
        panel += settingRow(t("privacy.hyperlink_auditing"), t("privacy.hyperlink_auditing.description"), check(QStringLiteral("disablePing"), context.privacyDisableHyperlinkAuditing));
        panel += QStringLiteral("</details><p><button class=\"primary\" type=\"submit\">%1</button> <a class=\"button secondary\" href=\"https://granger.local/__action/open?page=about:privacy\">%2</a> <a class=\"button secondary\" href=\"https://granger.local/__action/settings/clear-session\">%3</a></p></form>")
                     .arg(e(t("settings.save_privacy")), e(t("privacy.open_diagnostics")), e(t("settings.clear_cookies_cache")));
        panel += QStringLiteral("<details><summary>%1</summary>%2</details>")
                     .arg(e(t("tracker_protection.manual_policies")), context.contentBlockingDomainPoliciesHtml);
        panel += QStringLiteral("<details><summary>%1</summary>%2</details>")
                     .arg(e(t("tracker_protection.recent_events")), context.contentBlockingRecentEventsHtml);
        if (context.privacyPreset == QStringLiteral("strict")) {
            panel += QStringLiteral("<div class=\"warning\"><strong>%1</strong><p>%2</p></div>")
                         .arg(e(t("privacy.strict_warning_title")), e(t("privacy.strict_warning")));
        }

        panel += QStringLiteral("<section class=\"settings-subsection\" id=\"privacy-profiles\"><h3>%1</h3><form class=\"profile-activation\" action=\"https://granger.local/__action/privacy/profile/activate\" method=\"get\"><div class=\"field-copy\"><strong>%2</strong><span>%3</span></div><select name=\"name\" aria-label=\"%2\">%4</select><button type=\"submit\">%5</button></form><h4>%6</h4><div class=\"profile-management\"><form class=\"profile-create\" action=\"https://granger.local/__action/privacy/profile/create\" method=\"get\"><label class=\"field\"><span>%7</span><input type=\"text\" name=\"name\" placeholder=\"%7\"></label><label class=\"field\"><span>%8</span><select name=\"preset\"><option value=\"standard\">%9</option><option value=\"balanced\" selected>%10</option><option value=\"strict\">%11</option></select></label><button type=\"submit\">%12</button></form><div class=\"profile-secondary\"><form class=\"profile-inline\" action=\"https://granger.local/__action/privacy/profile/duplicate\" method=\"get\"><label class=\"field\"><span>%7</span><input type=\"text\" name=\"name\" placeholder=\"%7\"></label><button type=\"submit\">%13</button></form><form class=\"profile-inline\" action=\"https://granger.local/__action/privacy/profile/rename\" method=\"get\"><label class=\"field\"><span>%7</span><input type=\"text\" name=\"name\" placeholder=\"%7\"></label><button type=\"submit\">%14</button></form></div><a class=\"button secondary profile-reset\" href=\"https://granger.local/__action/privacy/profile/reset\">%15</a></div></section>")
                     .arg(e(t("privacy.config_profiles")), e(t("privacy.active_profile")),
                          e(t("privacy.active_profile.description")), context.privacyProfileOptionsHtml,
                          e(t("privacy.activate_profile")), e(t("privacy.profile_management")),
                          e(t("privacy.profile_name")), e(t("privacy.base_preset")),
                          e(t("privacy.preset.standard")), e(t("privacy.preset.balanced")),
                          e(t("privacy.preset.strict")), e(t("privacy.create_profile")),
                          e(t("privacy.duplicate_profile")), e(t("privacy.rename_profile")),
                          e(t("privacy.reset_defaults")));

        QString siteRuleControls;
        siteRuleControls += ruleSelect(QStringLiteral("javascript"), t("privacy.first_party_javascript"));
        siteRuleControls += ruleSelect(QStringLiteral("thirdPartyScripts"), t("privacy.third_party_javascript"));
        siteRuleControls += ruleSelect(QStringLiteral("firstPartyFrames"), t("privacy.first_party_frames"));
        siteRuleControls += ruleSelect(QStringLiteral("thirdPartyFrames"), t("privacy.third_party_frames_rule"));
        siteRuleControls += ruleSelect(QStringLiteral("webAssembly"), QStringLiteral("WebAssembly"));
        siteRuleControls += ruleSelect(QStringLiteral("webGl"), QStringLiteral("WebGL"));
        siteRuleControls += ruleSelect(QStringLiteral("canvasReadback"), t("privacy.canvas_readback"));
        siteRuleControls += ruleSelect(QStringLiteral("fullscreen"), t("privacy.fullscreen"));
        siteRuleControls += ruleSelect(QStringLiteral("cookies"), t("privacy.cookies"));
        siteRuleControls += ruleSelect(QStringLiteral("thirdPartyCookies"), t("privacy.third_party_cookies"));
        siteRuleControls += ruleSelect(QStringLiteral("webRtc"), QStringLiteral("WebRTC"));
        siteRuleControls += ruleSelect(QStringLiteral("fingerprint"), t("privacy.fingerprint"));
        siteRuleControls += ruleSelect(QStringLiteral("storage"), t("privacy.persistent_storage"));
        siteRuleControls += ruleSelect(QStringLiteral("autoplay"), t("privacy.autoplay"));
        siteRuleControls += ruleSelect(QStringLiteral("popups"), t("privacy.popups"));
        panel += QStringLiteral("<details class=\"settings-detail\" open id=\"site-rules\"><summary>%1</summary><div class=\"settings-detail-content\"><p>%2</p>")
                     .arg(e(t("privacy.site_rules")), e(t("privacy.site_rules.description")));
        panel += QStringLiteral("<form action=\"https://granger.local/__action/privacy/site-rule/save\" method=\"get\"><div class=\"form-grid site-rule-grid\"><label class=\"field rule-target\"><span>%1</span><input type=\"text\" name=\"match\" placeholder=\"https://example.com\"></label><label class=\"field\"><span>%2</span><select name=\"scope\"><option value=\"origin\">%3</option><option value=\"domain\">%4</option></select></label>%5<button class=\"grid-action\" type=\"submit\">%6</button></div></form>%7</div></details>")
                     .arg(e(t("privacy.site_address")), e(t("privacy.matching_scope")),
                          e(t("privacy.scope.origin")), e(t("privacy.scope.domain")),
                          siteRuleControls, e(t("common.save")), context.privacySiteRulesHtml);

        panel += QStringLiteral("<details class=\"settings-detail\" open id=\"site-permissions\"><summary>%1</summary><div class=\"settings-detail-content\"><p>%2</p><form action=\"https://granger.local/__action/privacy/permission/save\" method=\"get\"><div class=\"form-grid permission-grid\"><label class=\"field permission-origin\"><span>%3</span><input type=\"url\" name=\"origin\" placeholder=\"https://example.com\"></label><label class=\"field\"><span>%4</span><select name=\"profile\"><option value=\"normal\">%7</option><option value=\"private\">%8</option><option value=\"tor\">%9</option><option value=\"onion\">%10</option></select></label><label class=\"field\"><span>%5</span><select name=\"permission\"><option value=\"camera\">%11</option><option value=\"microphone\">%12</option><option value=\"geolocation\">%13</option><option value=\"notifications\">%14</option><option value=\"clipboard\">%15</option><option value=\"local-fonts\">%16</option><option value=\"file-system\">%17</option></select></label><label class=\"field\"><span>%6</span><select name=\"decision\"><option value=\"ask\">%18</option><option value=\"allow-session\">%19</option><option value=\"allow-always\">%20</option><option value=\"block\">%21</option></select></label><button class=\"grid-action\" type=\"submit\">%22</button></div></form>%23</div></details>")
                     .arg(e(t("privacy.site_permissions")), e(t("privacy.site_permissions.description")),
                          e(t("privacy.site_address")), e(t("privacy.permission_profile")),
                          e(t("privacy.permission_kind")), e(t("privacy.permission_decision")),
                          e(t("privacy.profile.normal")), e(t("privacy.profile.private")),
                          e(t("privacy.profile.tor")), e(t("privacy.profile.onion")),
                          e(t("privacy.permission.camera")), e(t("privacy.permission.microphone")),
                          e(t("privacy.permission.geolocation")), e(t("privacy.permission.notifications")),
                          e(t("privacy.permission.clipboard")), e(t("privacy.permission.local-fonts")),
                          e(t("privacy.permission.file_system")), e(t("privacy.permission.ask")),
                          e(t("privacy.permission.allow_session")), e(t("privacy.permission.always_allow")),
                          e(t("privacy.permission.block")), e(t("common.save")), context.privacyPermissionsHtml);

        panel += QStringLiteral("<details class=\"config-transfer\" id=\"privacy-config\"><summary>%1</summary><p>%2</p><div class=\"config-transfer-grid\"><section class=\"config-transfer-group\" aria-label=\"%3\"><h4 class=\"config-transfer-title\">%3</h4><div class=\"config-transfer-actions\"><a class=\"button\" href=\"https://granger.local/__action/privacy/config/import\">%3</a><a class=\"button secondary\" href=\"https://granger.local/__action/privacy/config/validate\">%4</a></div></section><section class=\"config-transfer-group\" aria-label=\"%6\"><h4 class=\"config-transfer-title\">%6</h4><form class=\"config-export-form\" action=\"https://granger.local/__action/privacy/config/export\" method=\"get\"><label class=\"check-row\"><input type=\"checkbox\" name=\"includeBridges\" value=\"1\"><span>%5</span></label><button type=\"submit\">%6</button></form></section></div><div class=\"config-preview\">%7</div></details>")
                     .arg(e(t("privacy.config_import_export")), e(t("privacy.config_import_export.description")),
                          e(t("privacy.import_config")), e(t("privacy.validate_config")),
                          e(t("privacy.include_bridges")), e(t("privacy.export_config")),
                          context.privacyImportPreviewHtml);
    } else if (category == QStringLiteral("containers")) {
        QString assignments;
        if (!context.containerOptionsHtml.trimmed().isEmpty()) {
            assignments = QStringLiteral(
                "<details class=\"settings-detail\" id=\"container-site-assignments\"><summary>%1</summary>"
                "<div class=\"settings-detail-content\"><p>%2</p>"
                "<form action=\"https://granger.local/__action/containers/assign-site\" method=\"get\">"
                "<div class=\"form-grid site-rule-grid\"><label class=\"field rule-target\"><span>%3</span>"
                "<input name=\"site\" placeholder=\"example.com\" required></label>"
                "<label class=\"field\"><span>%4</span><select name=\"container\">%5</select></label>"
                "<label class=\"check-row\"><input type=\"checkbox\" name=\"subdomains\" value=\"1\" checked>"
                "<span>%6</span></label><button class=\"grid-action\" type=\"submit\">%7</button></div></form>%8"
                "</div></details>")
                .arg(e(t("containers.site_assignments")),
                     e(t("containers.site_assignments.description")),
                     e(t("containers.site")), e(t("containers.container")),
                     context.containerOptionsHtml, e(t("containers.include_subdomains")),
                     e(t("common.save")), context.containerSiteRulesHtml);
        }
        panel = QStringLiteral(
            "<div class=\"settings-heading-actions\"><div><h2>%1</h2><p>%2</p></div>"
            "<a class=\"button primary\" href=\"https://granger.local/__action/containers/show-create\">%3</a>"
            "</div>%4%5")
            .arg(e(t("containers.title")), e(t("containers.description")),
                 e(t("containers.create")), context.containersHtml, assignments);
    } else if (category == QStringLiteral("isolated")) {
        panel = QStringLiteral("<h2>%1</h2><p>%2</p><div class=\"warning\"><strong>%3</strong><p>%4</p></div><p><a class=\"button primary\" href=\"https://granger.local/__action/isolated/new\">%5</a></p>")
                    .arg(e(t("isolated.title")), e(t("isolated.description")),
                         e(t("isolated.memory_only")), e(t("isolated.memory_only.description")),
                         e(t("isolated.new_tab")));
    } else if (category == QStringLiteral("pamp")) {
        panel = QStringLiteral("<h2>%1</h2><p>%2</p><div class=\"warning\"><strong>%3</strong><p>%4</p></div><p><a class=\"button primary\" href=\"https://granger.local/__action/pamp/analyze\">%5</a></p>")
                    .arg(e(t("pamp.title")), e(t("pamp.description")), e(t("pamp.passive_only")),
                         e(t("pamp.passive_only.description")), e(t("pamp.analyze_current")));
    } else if (category == QStringLiteral("connection")) {
        panel = QStringLiteral(
            "<h2>%1</h2>"
            "<section class=\"settings-surface settings-connection-status\">"
            "<div class=\"settings-surface-header\"><h3>%2</h3></div>"
            "<div class=\"settings-surface-body flush\"><div class=\"info-list\">%3%4%5</div></div>"
            "</section>"
            "<section class=\"settings-surface settings-connection-strategy\">"
            "<div class=\"settings-surface-header\"><h3>%6</h3></div>"
            "<div class=\"settings-surface-body\"><div class=\"settings-strategy-grid\">"
            "<a class=\"button primary\" href=\"https://granger.local/__action/connection/apply?mode=automatic\">%7</a>"
            "<a class=\"button\" href=\"https://granger.local/__action/connection/apply?mode=direct\">%8</a>"
            "<a class=\"button\" href=\"https://granger.local/__action/connection/apply?mode=snowflake\">%9</a>"
            "</div></div></section>"
            "<section class=\"settings-surface settings-connection-bridges\">"
            "<div class=\"settings-surface-header\"><h3>%10</h3></div>"
            "<form action=\"https://granger.local/__action/bridges/save\" method=\"get\">"
            "<div class=\"settings-surface-body\"><label class=\"settings-surface-field\"><span>%11</span>"
            "<input type=\"text\" name=\"line\" placeholder=\"%11\"></label></div>"
            "<div class=\"settings-surface-footer\"><button type=\"submit\">%12</button>"
            "<a class=\"button secondary\" href=\"https://granger.local/__action/bridges/import-qr\">%13</a>"
            "<a class=\"button primary\" href=\"https://granger.local/__action/bridges/apply\">%14</a>"
            "<a class=\"button secondary\" href=\"https://granger.local/__action/open?page=about:bridges\">%15</a>"
            "</div></form></section>"
            "<section class=\"settings-surface settings-connection-external\">"
            "<div class=\"settings-surface-header\"><h3>%16</h3></div>"
            "<form action=\"https://granger.local/__action/connection/save-external\" method=\"get\">"
            "<div class=\"settings-surface-body\"><label class=\"settings-surface-field\"><span>%16</span>"
            "<input type=\"url\" name=\"url\" value=\"%17\" placeholder=\"socks5://127.0.0.1:9050\"></label></div>"
            "<div class=\"settings-surface-footer\"><button type=\"submit\">%18</button></div>"
            "</form></section>")
                    .arg(e(t("settings.category.connection")), e(t("label.status")),
                         infoRow(t("label.route"), s(context.currentRoute), QStringLiteral("settings-route")),
                         infoRow(t("label.tor"), s(context.torState), QStringLiteral("settings-tor-state")),
                         infoRow(t("label.bootstrap"), s(context.bridgeBootstrap), QStringLiteral("settings-bootstrap")),
                         e(t("settings.connection_strategy")), e(t("settings.automatic")), e(t("settings.tor_direct")),
                         e(t("settings.snowflake")), e(t("page.bridges.title")), e(t("bridges.paste_line")),
                         e(t("common.save")), e(t("bridges.import_qr")), e(t("common.apply")), e(t("common.manage")),
                         e(t("settings.external_tor")), e(context.externalTorSocksUrl), e(t("settings.save_endpoint")));
    } else if (category == QStringLiteral("downloads")) {
        panel = QStringLiteral("<h2>%1</h2><p>%2</p><a class=\"button primary\" href=\"https://granger.local/__action/open?page=about:downloads\">%3</a>")
                    .arg(e(t("page.downloads.title")), e(t("settings.downloads_description")), e(t("settings.open_downloads")));
    } else if (category == QStringLiteral("reports")) {
        panel = QStringLiteral("<h2>%1</h2>%2")
                    .arg(e(t("settings.category.reports")), context.reportsLogsHtml);
    } else if (category == QStringLiteral("advanced")) {
        const auto selectControl = [](const QString &name,
                                      const QString &current,
                                      const QVector<QPair<QString, QString>> &options) {
            QString html = QStringLiteral("<select name=\"%1\">").arg(e(name));
            for (const auto &option : options) {
                html += QStringLiteral("<option value=\"%1\"%2>%3</option>")
                            .arg(e(option.first), option.first == current ? QStringLiteral(" selected") : QString(),
                                 e(option.second));
            }
            return html + QStringLiteral("</select>");
        };
        const auto checkbox = [](const QString &name, bool checked) {
            return QStringLiteral("<input type=\"checkbox\" name=\"%1\" value=\"1\"%2>")
                .arg(e(name), checked ? QStringLiteral(" checked") : QString());
        };
        QString uaProfile = context.userAgentProfile;
        if (uaProfile == QStringLiteral("default") || uaProfile == QStringLiteral("chrome-compatible")) {
            uaProfile = QStringLiteral("standard");
        }
        const QString uaSelect = selectControl(QStringLiteral("profile"), uaProfile, {
            {QStringLiteral("standard"), t("settings.ua_standard")},
            {QStringLiteral("tor"), t("settings.ua_tor")},
            {QStringLiteral("compatibility"), t("settings.ua_compatibility")},
            {QStringLiteral("custom"), t("settings.ua_custom")}
        });
        panel = QStringLiteral("<h2>%1</h2>").arg(e(t("settings.category.advanced")));
        panel += QStringLiteral("<form action=\"https://granger.local/__action/settings/user-agent\" method=\"get\"><h3>%1</h3>")
                     .arg(e(t("settings.identity_title")));
        panel += settingRow(t("settings.user_agent_profile"), t("settings.user_agent_profile.description"), uaSelect);
        panel += settingRow(t("settings.custom_user_agent"), t("settings.custom_user_agent.description"),
                            QStringLiteral("<input type=\"text\" name=\"custom\" value=\"%1\">")
                                .arg(e(context.customUserAgent)));
        panel += QStringLiteral("<div class=\"warning\"><strong>%1</strong><p>%2</p></div><p><button class=\"primary\" type=\"submit\">%3</button></p></form>")
                     .arg(e(t("settings.compatibility_only")), e(t("settings.compatibility_warning")),
                          e(t("settings.apply_user_agent")));

        panel += QStringLiteral("<form action=\"https://granger.local/__action/settings/fingerprint-surfaces\" method=\"get\"><h3>%1</h3>")
                     .arg(e(t("fingerprint.settings_title")));
        panel += settingRow(t("fingerprint.webgl"), t("fingerprint.webgl.description"),
                            selectControl(QStringLiteral("webgl"), context.webGlProtectionMode, {
                                {QStringLiteral("compatibility"), t("fingerprint.mode.compatibility")},
                                {QStringLiteral("balanced"), t("fingerprint.mode.balanced")},
                                {QStringLiteral("strict"), t("fingerprint.mode.strict")}}));
        panel += settingRow(t("fingerprint.canvas"), t("fingerprint.canvas.description"),
                            selectControl(QStringLiteral("canvas"), context.canvasProtectionMode, {
                                {QStringLiteral("compatibility"), t("fingerprint.mode.compatibility")},
                                {QStringLiteral("protected"), t("fingerprint.mode.protected")},
                                {QStringLiteral("block-readback"), t("fingerprint.mode.block_readback")}}));
        panel += settingRow(t("fingerprint.audio"), t("fingerprint.audio.description"),
                            selectControl(QStringLiteral("audio"), context.audioProtectionMode, {
                                {QStringLiteral("compatibility"), t("fingerprint.mode.compatibility")},
                                {QStringLiteral("protected"), t("fingerprint.mode.protected")},
                                {QStringLiteral("restricted"), t("fingerprint.mode.restricted")}}));
        panel += settingRow(t("fingerprint.screen"), t("fingerprint.screen.description"),
                            selectControl(QStringLiteral("screen"), context.screenExposureMode, {
                                {QStringLiteral("actual"), t("fingerprint.mode.actual")},
                                {QStringLiteral("rounded"), t("fingerprint.mode.rounded")},
                                {QStringLiteral("standardized"), t("fingerprint.mode.standardized")}}));
        panel += settingRow(t("fingerprint.timezone"), t("fingerprint.timezone.description"),
                            selectControl(QStringLiteral("timezone"), context.timezoneMode, {
                                {QStringLiteral("system"), t("fingerprint.mode.system")},
                                {QStringLiteral("utc"), QStringLiteral("UTC")}}));
        panel += settingRow(t("fingerprint.hardware"), t("fingerprint.hardware.description"),
                            selectControl(QStringLiteral("hardware"), context.hardwareExposureMode, {
                                {QStringLiteral("actual"), t("fingerprint.mode.actual")},
                                {QStringLiteral("standardized"), t("fingerprint.mode.standardized")}}));
        panel += settingRow(t("fingerprint.window_size"),
                            t("fingerprint.window_size.description"),
                            selectControl(QStringLiteral("windowSize"),
                                          context.windowSizeProtectionMode, {
                                {QStringLiteral("profile"), t("fingerprint.window_size.profile")},
                                {QStringLiteral("on"), t("fingerprint.window_size.on")},
                                {QStringLiteral("off"), t("fingerprint.window_size.off")}}));
        panel += QStringLiteral("<p><button class=\"primary\" type=\"submit\">%1</button></p></form>")
                     .arg(e(t("fingerprint.apply")));

        panel += QStringLiteral("<form action=\"https://granger.local/__action/settings/developer-tools\" method=\"get\"><h3>%1</h3>")
                     .arg(e(t("developer_tools.title")));
        panel += settingRow(t("developer_tools.enable"), t("developer_tools.enable.description"),
                            checkbox(QStringLiteral("enabled"), context.developerToolsEnabled));
        panel += settingRow(t("developer_tools.dock"), t("developer_tools.dock.description"),
                            selectControl(QStringLiteral("dock"), context.developerToolsDockPosition, {
                                {QStringLiteral("right"), t("developer_tools.dock.right")},
                                {QStringLiteral("bottom"), t("developer_tools.dock.bottom")},
                                {QStringLiteral("window"), t("developer_tools.dock.window")}}));
        panel += settingRow(t("developer_tools.f12"), t("developer_tools.f12.description"),
                            checkbox(QStringLiteral("f12"), context.developerToolsOpenWithF12));
        panel += settingRow(t("developer_tools.inspect"), t("developer_tools.inspect.description"),
                            checkbox(QStringLiteral("inspect"), context.developerToolsAllowInspect));
        panel += settingRow(t("developer_tools.disable_private"), t("developer_tools.disable_private.description"),
                            checkbox(QStringLiteral("disablePrivate"), context.developerToolsDisabledInPrivateProfiles));
        panel += settingRow(t("developer_tools.allow_internal"), t("developer_tools.allow_internal.description"),
                            checkbox(QStringLiteral("allowInternal"), context.developerToolsAllowInternalPages));
        panel += QStringLiteral("<p><button class=\"primary\" type=\"submit\">%1</button></p></form>")
                     .arg(e(t("developer_tools.apply")));
        panel += QStringLiteral("<details><summary>%1</summary><div class=\"info-list\">%2%3</div></details>")
                     .arg(e(t("settings.local_data_paths")), infoRow(t("label.application_data"), context.dataRoot),
                          infoRow(t("label.webengine_profile"), context.profileRoot));
    } else if (category == QStringLiteral("danger")) {
        const QString dangerMessage = context.message.trimmed().isEmpty()
            ? QStringLiteral("<div id=\"danger-form-message\" class=\"danger-form-message\" role=\"status\" aria-live=\"polite\"></div>")
            : QStringLiteral("<div id=\"danger-form-message\" class=\"danger-form-message\" role=\"alert\" aria-live=\"assertive\">%1</div>")
                  .arg(e(context.message));
        if (context.wipeConfirmationStage) {
            const QString confirmationPhrase = context.wipeConfirmationPhrase;
            const QString confirmationDescription =
                t("danger.confirm_description").arg(confirmationPhrase);
            panel = QStringLiteral("<h2>%1</h2><div id=\"danger-confirm-help\" class=\"warning error\"><strong>%2</strong><p>%3</p></div><form class=\"danger-confirm-form\" action=\"https://granger.local/__action/danger/wipe-confirm\" method=\"get\"><input type=\"hidden\" name=\"deleteDownloads\" value=\"%4\"><label class=\"field\"><span>%5</span><input class=\"danger-phrase-input\" type=\"text\" name=\"phrase\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" required autofocus aria-describedby=\"danger-confirm-help danger-form-message\" placeholder=\"%6\"></label>%7<p><button class=\"danger-fill\" type=\"submit\">%8</button></p></form>")
                        .arg(e(t("danger.title")), e(t("danger.confirm_title")),
                             e(confirmationDescription),
                             context.wipeDeleteDownloads ? QStringLiteral("1") : QStringLiteral("0"),
                             e(t("danger.type_phrase")), e(confirmationPhrase),
                             dangerMessage, e(t("danger.continue")));
        } else {
            panel = QStringLiteral("<h2>%1</h2><div class=\"warning error\"><strong>%2</strong><p>%3</p><p>%4</p></div><div class=\"info-list\">%5%6</div>%7<form action=\"https://granger.local/__action/danger/wipe-review\" method=\"get\"><label class=\"check-row\"><input type=\"checkbox\" name=\"understand\" value=\"1\" required><span>%8</span></label><label class=\"check-row\"><input type=\"checkbox\" name=\"deleteDownloads\" value=\"1\"><span>%9</span></label><p><button class=\"danger-fill\" type=\"submit\">%10</button></p></form>")
                        .arg(e(t("danger.title")), e(t("danger.warning_title")),
                             e(t("danger.warning")), e(t("danger.forensic_warning")),
                             infoRow(t("danger.browser_data"), t("danger.browser_data_list")),
                             infoRow(t("danger.tracked_downloads"), QString::number(context.trackedDownloadCount)),
                             dangerMessage, e(t("danger.understand")),
                             e(t("danger.delete_download_files")), e(t("danger.review")));
        }
    } else if (category == QStringLiteral("about")) {
        panel = QStringLiteral("<h2>%1</h2><div class=\"info-list\">%2%3%4</div><p>%5</p>")
                    .arg(e(t("settings.about_title")), infoRow(t("label.version"), context.applicationVersion),
                         infoRow(t("label.browser_engine"), QStringLiteral("Qt WebEngine / Chromium")),
                         infoRow(t("label.user_agent_mode"), context.userAgentProfile), e(t("settings.about_description")));
    } else {
        const QString englishSelected = context.language == QStringLiteral("en") ? QStringLiteral(" selected") : QString();
        const QString russianSelected = context.language == QStringLiteral("ru") ? QStringLiteral(" selected") : QString();
        const QString kazakhSelected = context.language == QStringLiteral("kk") ? QStringLiteral(" selected") : QString();
        const QString languageSelect = QStringLiteral("<select class=\"language-select\" name=\"language\"><option value=\"en\"%1>%2</option><option value=\"ru\"%3>%4</option><option value=\"kk\"%5>%6</option></select>")
                                           .arg(englishSelected, e(t("settings.language.english")),
                                                russianSelected, e(t("settings.language.russian")),
                                                kazakhSelected, e(t("settings.language.kazakh")));
        panel = QStringLiteral("<h2>%1</h2><form action=\"https://granger.local/__action/settings/general\" method=\"get\">%2%3%4<p><button class=\"primary\" type=\"submit\">%5</button></p></form>")
                    .arg(e(t("settings.category.general")),
                         settingRow(t("settings.language"), t("settings.language.description"), languageSelect),
                         settingRow(t("settings.home_page"), t("settings.home_page.description"), QStringLiteral("<input type=\"text\" name=\"home\" value=\"%1\">").arg(e(context.homeUrl))),
                         settingRow(t("settings.sidebar_pinned"), t("settings.sidebar_pinned.description"), QStringLiteral("<input type=\"checkbox\" name=\"sidebarPinned\" value=\"1\"%1>").arg(context.sidebarPinned ? QStringLiteral(" checked") : QString())),
                         e(t("settings.save_general")));
    }
    return settingsPage(chrome(t("page.settings.title"), t("page.settings.subtitle"),
                               (category == QStringLiteral("danger")
                                    ? QString() : messageBlock(context.message))
                                   + QStringLiteral("<section class=\"settings-shell\"><nav class=\"settings-nav\">%1</nav><section class=\"settings-panel\">%2</section></section>")
                                         .arg(nav, panel)));
}

QString InternalPages::network(const InternalPageContext &context)
{
    return chrome(t("page.network.title"), t("page.network.subtitle"), QStringLiteral("<div class=\"status-page ds-page-stack\"><section class=\"ds-card ds-info-card\"><div class=\"info-list\">%1%2%3</div></section></div>").arg(infoRow(t("label.proxy"), s(context.proxyState)), infoRow(t("label.route"), s(context.currentRoute)), infoRow(t("label.state"), s(context.routeState))));
}

QString InternalPages::reports(const InternalPageContext &context)
{
    const QString legacy = QStringLiteral("<details class=\"ds-card ds-disclosure-card\"><summary>%1</summary><div class=\"info-list\">%2%3%4</div></details>")
        .arg(e(t("reports.search_artifacts")),
             infoRow(t("label.module"), context.searchImplementation),
             infoRow(t("label.results"), context.resultsPath),
             infoRow(t("label.report"), context.reportPath));
    return chrome(t("page.reports.title"), t("page.reports.subtitle"),
                  messageBlock(context.message)
                      + QStringLiteral("<div class=\"reports-page ds-page-stack\">%1%2</div>")
                            .arg(context.reportsLogsHtml, legacy));
}

QString InternalPages::downloads(const InternalPageContext &context)
{
    const QString items = context.downloadsHtml.isEmpty()
        ? QStringLiteral("<div class=\"ds-card ds-empty-card\"><p>%1</p></div>").arg(e(t("downloads.none")))
        : context.downloadsHtml;
    const QString body = messageBlock(context.message)
        + QStringLiteral("<div class=\"downloads-page ds-page-stack\"><div class=\"ds-action-bar\"><a class=\"button secondary\" href=\"https://granger.local/__action/downloads/clear\">%1</a></div><section class=\"ds-card-list\">%2</section></div>")
              .arg(e(t("downloads.clear_completed")), items);
    return chrome(t("page.downloads.title"), t("page.downloads.subtitle"), body);
}

QString InternalPages::cookies(const InternalPageContext &context)
{
    const QString encodedFilter = QString::fromLatin1(QUrl::toPercentEncoding(context.cookieFilter));
    const QString querySuffix = encodedFilter.isEmpty() ? QString() : QStringLiteral("?filter=%1").arg(encodedFilter);
    const QString clearAction = context.cookieFilter.isEmpty()
        ? QString()
        : QStringLiteral("<a class=\"button secondary\" href=\"https://granger.local/__action/cookies/clear-filter\">%1</a>")
              .arg(e(t("common.clear")));
    QString confirmation;
    if (context.cookieDeleteConfirmation) {
        confirmation = QStringLiteral("<section class=\"cookie-confirm\" role=\"alert\"><strong>%1</strong><p>%2</p><div class=\"row\"><a class=\"button danger-fill\" href=\"https://granger.local/__action/cookies/delete-all-confirmed\">%3</a><a class=\"button secondary\" href=\"https://granger.local/__action/cookies/delete-all-cancel%4\">%5</a></div></section>")
                           .arg(e(t("cookies.confirm_delete_all_title")),
                                e(t("cookies.confirm_delete_all_message")),
                                e(t("cookies.confirm_delete_all")), querySuffix,
                                e(t("common.cancel")));
    }
    const QString toolbar = QStringLiteral("<form class=\"cookie-toolbar\" action=\"https://granger.local/__action/cookies/filter\" method=\"get\"><div class=\"cookie-filter\"><input type=\"text\" name=\"value\" value=\"%1\" placeholder=\"%2\" aria-label=\"%2\"><button type=\"submit\">%3</button>%4</div><div class=\"cookie-toolbar-actions\"><a class=\"button secondary\" href=\"https://granger.local/__action/cookies/refresh%5\">%6</a><a class=\"button danger\" href=\"https://granger.local/__action/cookies/delete-all%5\">%7</a></div></form>")
                                .arg(e(context.cookieFilter), e(t("cookies.filter_placeholder")),
                                     e(t("common.filter")), clearAction, querySuffix,
                                     e(t("common.refresh")), e(t("cookies.delete_all")));
    const QString body = messageBlock(context.message) + confirmation + toolbar
        + QStringLiteral("<p class=\"cookie-count\">%1</p><section>%2</section>")
              .arg(e(t("cookies.count")).arg(context.cookieCount), context.cookiesHtml);
    return chrome(t("page.cookies.title"), t("page.cookies.subtitle"), body);
}

QString InternalPages::bookmarks(const InternalPageContext &context)
{
    const QString content = context.bookmarksHtml.isEmpty()
        ? QStringLiteral("<div class=\"ds-card ds-empty-card\"><p>%1</p></div>").arg(e(t("bookmarks.none")))
        : context.bookmarksHtml;
    const QString body = messageBlock(context.message)
        + QStringLiteral("<div class=\"bookmark-page ds-page-stack\">%1</div>").arg(content);
    return chrome(t("page.bookmarks.title"), t("page.bookmarks.subtitle"), body);
}

QString InternalPages::history(const InternalPageContext &context)
{
    QString body = messageBlock(context.message);
    if (context.historyHtml.isEmpty()) {
        body += QStringLiteral(
            "<section class=\"history-empty empty-state\"><div class=\"empty-state-icon\" "
            "aria-hidden=\"true\">&#8634;</div><h2>%1</h2></section>")
                    .arg(e(t("history.none")));
    } else {
        body += QStringLiteral(
            "<div class=\"history-toolbar\"><a class=\"button danger\" "
            "href=\"https://granger.local/__action/history/clear\">%1</a></div>"
            "<div class=\"history-timeline\">%2</div>")
                    .arg(e(t("history.clear")), context.historyHtml);
    }
    QString html = chrome(t("page.history.title"), t("page.history.subtitle"), body);
    html.replace(QStringLiteral("</style>"), QStringLiteral(R"CSS(
.history-toolbar{display:flex;justify-content:flex-end;margin:0 0 24px;padding:0 0 18px;border-bottom:1px solid var(--ds-border-subtle)}
.history-timeline{display:grid;gap:28px}
.history-group{min-width:0}
.history-date{margin:0 0 10px;color:var(--ds-text-secondary);font-size:13px;font-weight:650}
.history-list{overflow:hidden;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-lg);background:var(--ds-bg-surface)}
.history-row{min-width:0;border-bottom:1px solid var(--ds-border-subtle)}
.history-row:last-child{border-bottom:0}
.history-link{display:grid;grid-template-columns:36px minmax(0,1fr) auto;gap:12px;align-items:center;min-height:62px;padding:10px 14px;color:var(--ds-text);text-decoration:none;transition:background-color var(--ds-fast) ease}
.history-link:hover{background:var(--ds-bg-hover)}
.history-link:focus-visible{position:relative;z-index:1;outline:2px solid var(--ds-focus);outline-offset:-2px}
.history-site-icon{display:grid;place-items:center;width:34px;height:34px;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-md);background:var(--ds-accent-soft);color:var(--ds-text-secondary);font-size:13px;font-weight:700;text-transform:uppercase}
.history-copy{display:grid;gap:2px;min-width:0}
.history-title{min-width:0;overflow:hidden;color:var(--ds-text);font-size:13px;font-weight:620;text-overflow:ellipsis;white-space:nowrap}
.history-location{min-width:0;overflow:hidden;color:var(--ds-text-muted);font-size:11px;text-overflow:ellipsis;white-space:nowrap}
.history-time{padding-left:12px;color:var(--ds-text-muted);font-size:11px;white-space:nowrap}
.history-empty{min-height:180px;border:1px solid var(--ds-border-subtle);border-radius:var(--ds-radius-lg);background:var(--ds-bg-surface)}
.history-empty h2{margin:0;font-size:16px}
@media(max-width:560px){.history-toolbar{justify-content:stretch}.history-toolbar .button{width:100%}.history-link{grid-template-columns:34px minmax(0,1fr);gap:10px;padding:10px 11px}.history-time{grid-column:2;padding:0}.history-site-icon{width:32px;height:32px}}
@media(prefers-reduced-motion:reduce){.history-link{transition:none!important}}
</style>)CSS"));
    return html;
}

QString InternalPages::siteInfo(const InternalPageContext &context)
{
    return chrome(t("page.site_info.title"), t("page.site_info.subtitle"),
                  QStringLiteral("<div class=\"site-info-page ds-page-stack\">%1</div>")
                      .arg(context.siteInfoHtml));
}

QString InternalPages::siteAnalysis(const InternalPageContext &context)
{
    return chrome(t("pamp.title"), t("pamp.subtitle"),
                  messageBlock(context.message)
                      + QStringLiteral("<div class=\"analysis-page\">%1</div>")
                            .arg(context.pampReportHtml));
}

QString InternalPages::searchResults(const InternalPageContext &context)
{
    const QString results = context.resultsHtml.isEmpty()
        ? QStringLiteral("<div class=\"ds-card ds-empty-card\"><p>%1</p></div>").arg(e(t("search.none")))
        : context.resultsHtml;
    return chrome(t("page.search_results.title"), context.resultsQuery,
                  messageBlock(context.message)
                      + QStringLiteral("<section class=\"results-page ds-card-list\">%1</section>")
                            .arg(results));
}

QString InternalPages::simple(const QString &title, const QString &subtitle, const QString &body)
{
    return chrome(title, subtitle,
                  QStringLiteral("<div class=\"simple-page ds-page-stack\">%1</div>").arg(body));
}

}
