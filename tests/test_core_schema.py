from core.schema import SchemaLoader


class TestSchemaLoader:
    def test_init_default(self):
        loader = SchemaLoader()
        assert loader.schema_path.endswith("api_schema.json")
        assert not loader.is_loaded

    def test_load_schema_missing_file(self):
        loader = SchemaLoader(schema_path="/invalid/path/to/schema.json")
        assert loader.schema == {}
        assert loader.is_loaded is False

    def test_load_schema_invalid_json(self, tmp_path):
        bad_json_file = tmp_path / "bad_schema.json"
        bad_json_file.write_text("{ invalid json }")

        loader = SchemaLoader(schema_path=str(bad_json_file))
        assert loader.schema == {}
        assert loader.is_loaded is False

    def test_load_schema_valid_json(self, tmp_path):
        valid_json_file = tmp_path / "valid_schema.json"
        valid_json_file.write_text('{"endpoints": {"read": ["a"], "write": ["b"]}}')

        loader = SchemaLoader(schema_path=str(valid_json_file))
        assert loader.schema == {"endpoints": {"read": ["a"], "write": ["b"]}}
        assert loader.is_loaded is True
        assert loader.endpoint_count == (1, 1)

    def test_generate_system_prompt_empty(self):
        loader = SchemaLoader(schema_path="/invalid/path")
        prompt = loader.generate_system_prompt()
        assert "expert reverse engineering AI agent" in prompt

    def test_generate_system_prompt_with_data(self, tmp_path):
        json_file = tmp_path / "schema.json"
        json_file.write_text('{"system_prompt": "Custom prompt.", "endpoints": {"test": 1}}')
        loader = SchemaLoader(schema_path=str(json_file))
        prompt = loader.generate_system_prompt(tool_instructions="Use these tools.")
        assert "Custom prompt." in prompt
        assert "Available API Endpoints" in prompt
        assert "Use these tools." in prompt
