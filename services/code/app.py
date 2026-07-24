import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from models.codebert_classifier import CodeBERTClassifier
from models.codet5_fixer import CodeT5Fixer
from utils.explanation_kb import ExplanationKB

app = Flask(__name__)
CORS(app)

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models', 'weights')

classifier = CodeBERTClassifier()
fixer = CodeT5Fixer()
explanation_kb = ExplanationKB()


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'models': {
            'classifier': classifier.is_loaded(),
            'fixer': fixer.is_loaded()
        }
    })


@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        code = data.get('code', '')

        if not code:
            return jsonify({'error': 'No code provided'}), 400

        classification = classifier.classify(code)

        suggested_fix = None
        fix_confidence = None
        if classification['prediction'] != 'not_vulnerable':
            fix_result = fixer.generate_fix(code, classification['prediction'])
            suggested_fix = fix_result.get('fix')
            fix_confidence = fix_result.get('confidence')

        explanation = explanation_kb.build_structured_explanation(
            vulnerability_type=classification['prediction'],
            code_snippet=code,
            confidence=classification['confidence'],
            detection_source='codebert_model',
            suggested_fix=suggested_fix
        )

        return jsonify({
            'prediction': classification['prediction'],
            'confidence': classification['confidence'],
            'top_predictions': classification['top_predictions'],
            'explanation': explanation,
            'suggested_fix': suggested_fix,
            'fix_confidence': fix_confidence
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/fix', methods=['POST'])
def fix():
    try:
        data = request.get_json()
        code = data.get('code', '')
        vulnerability_type = data.get('type', '')

        if not code:
            return jsonify({'error': 'No code provided'}), 400

        fix_result = fixer.generate_fix(code, vulnerability_type)

        return jsonify({
            'fix': fix_result.get('fix'),
            'confidence': fix_result.get('confidence'),
            'original_code': code
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/train', methods=['POST'])
def train():
    try:
        data = request.json
        model_type = data.get('model_type', 'classifier')

        if model_type == 'classifier':
            data_path = data.get('data_path', 'data/cve_dataset.csv')
            result = classifier.train(data_path)
        elif model_type == 'fixer':
            data_path = data.get('data_path', 'data/fixes_dataset.csv')
            result = fixer.train(data_path)
        else:
            return jsonify({'error': 'Invalid model type'}), 400

        return jsonify({'status': 'training_complete', 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
