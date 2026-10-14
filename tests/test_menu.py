from unittest.mock import patch

from zabbix_autodiscovery.menu import interactive_menu, prompt_choice, prompt_string, prompt_yes_no


def test_prompt_helpers():
    with patch("builtins.input", return_value="5"):
        assert prompt_choice("Escolha", "1") == "5"

    with patch("builtins.input", return_value=""):
        assert prompt_choice("Escolha", "1") == "1"

    with patch("builtins.input", return_value="custom.csv"):
        assert prompt_string("Arquivo", "default.csv") == "custom.csv"

    with patch("builtins.input", return_value=""):
        assert prompt_string("Arquivo", "default.csv") == "default.csv"

    with patch("builtins.input", return_value="s"):
        assert prompt_yes_no("Confirmar", default=False) is True

    with patch("builtins.input", return_value="n"):
        assert prompt_yes_no("Confirmar", default=True) is False

    with patch("builtins.input", return_value=""):
        assert prompt_yes_no("Confirmar", default=True) is True


def test_interactive_menu_exit():
    # Selecting "0" should exit immediately with 0
    with patch("builtins.input", return_value="0"):
        ret = interactive_menu("config.yaml")
        assert ret == 0


def test_interactive_menu_dispatches_check(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("zabbix:\n  url: http://fake\nscan:\n  networks: [192.168.0.0/24]\n", encoding="utf-8")

    # User selects "2" (check), then "0" (exit)
    inputs = iter(["2", "", "0"])
    with patch("builtins.input", side_effect=lambda *args: next(inputs)):
        with patch("zabbix_autodiscovery.cli.cmd_check") as mock_check:
            ret = interactive_menu(str(cfg_file))
            assert ret == 0
            assert mock_check.called



def test_interactive_menu_has_no_html_map_option(tmp_path, capsys):
    # The interactive map lives only inside Zabbix (native maps + frontend module): no option 15
    inputs = iter(["15", "", "0"])
    with patch("builtins.input", side_effect=lambda *args: next(inputs)):
        assert interactive_menu(str(tmp_path / "missing.yaml")) == 0
    assert "inválida" in capsys.readouterr().out


def test_menu_dependencies_requires_confirmation(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("zabbix:\n  url: http://fake\nscan:\n  networks: [192.168.0.0/24]\n", encoding="utf-8")
    # "12" dependencies, "2" apply, "n" do not confirm, ENTER (pause), "0" exit
    inputs = iter(["12", "2", "n", "", "0"])
    with patch("builtins.input", side_effect=lambda *args: next(inputs)):
        with patch("zabbix_autodiscovery.cli.cmd_dependencies") as mock_dep:
            assert interactive_menu(str(cfg_file)) == 0
            assert not mock_dep.called
