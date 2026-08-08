#pragma once

#include <QDialog>
#include <QString>

class QCheckBox;
class QFrame;
class QLabel;
class QLineEdit;
class QMouseEvent;
class QPushButton;
class QShowEvent;
class QTextEdit;
class QToolButton;

namespace granger {

struct ContainerDefinition;

struct ContainerEditorValues {
    QString name;
    QString color;
    QString icon;
    QString description;
    QString site;
    bool includeSubdomains = true;
};

class ContainerEditorDialog final : public QDialog {
public:
    explicit ContainerEditorDialog(const ContainerDefinition *existing,
                                   QWidget *parent = nullptr);

    ContainerEditorValues values() const;
    void setValidationError(const QString &message);

protected:
    void showEvent(QShowEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

private:
    bool isDirty() const;
    void setSelectedColor(const QString &color);
    void setSelectedIcon(const QString &icon);

    QFrame *m_surface = nullptr;
    QLineEdit *m_name = nullptr;
    QLabel *m_error = nullptr;
    QToolButton *m_iconPicker = nullptr;
    QTextEdit *m_description = nullptr;
    QLineEdit *m_site = nullptr;
    QCheckBox *m_subdomains = nullptr;
    QPushButton *m_accept = nullptr;
    QString m_selectedColor;
    QString m_selectedIcon;
    ContainerEditorValues m_initial;
};

}
