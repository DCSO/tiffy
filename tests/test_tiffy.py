import pytest
from click.testing import CliRunner
from tiffy import init


@pytest.mark.describe('tiffy')
class TestTiffy:
    @pytest.mark.it('Should create a new ioc from an observation received from TIE.')
    def test_init_invalid_actor_family_category_source(self):
        runner = CliRunner()
        result = runner.invoke(init, '--actor notvalid,,stillnot')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--category notvalid.stillnot')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--family notvalid#stillnot')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--source notvalid,;,stillnot')
        assert 'Error starting tiffy.py:' in result.output

    def test_init_invalid_first_last_date(self):
        runner = CliRunner()
        result = runner.invoke(init, '--first-seen 12.3.14')
        assert 'Error starting tiffy.py:' in result.output

        runner = CliRunner()
        result = runner.invoke(init, '--last-seen 12.3.14')
        assert 'Error starting tiffy.py:' in result.output

    def test_init_invalid_output_format(self):
        runner = CliRunner()
        result = runner.invoke(init, '--output-format XML')
        assert 'Error: Invalid value' in result.output

    def test_init_invalid_event_tags(self):
        runner = CliRunner()
        result = runner.invoke(init, '--event-tags tlp:amber')
        assert isinstance(result.exception, RuntimeError)

    def test_init_invalid_saverity_confindence(self):
        runner = CliRunner()
        result = runner.invoke(init, '--min-confidence -1')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--max-confidence 1000')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--min-severity -1')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--max-severity 10000')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--min-confidence 4 --max-confidence 2')
        assert 'Error starting tiffy.py:' in result.output
        runner = CliRunner()
        result = runner.invoke(init, '--min-severity 4 --max-severity 2')
        assert 'Error starting tiffy.py:' in result.output
