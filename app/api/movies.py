from flask import Blueprint, make_response, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.exceptions import abort
from ..models import Movies
from config import Config

movies_bp = Blueprint('movies', __name__)

# Fetches list of movies based on trendings which has (> 95%) users ratings
@movies_bp.route(Config.TRENDING_NOW, methods=['GET'])
@jwt_required()
def trending_now():
    username = get_jwt_identity()
    movies = Movies.objects()
    trending = [movie for movie in movies if movie.ratings > 95]
    return make_response(jsonify(trending), 200)

# Fetches list of movies based on username
@movies_bp.route(Config.FETCH_MOVIES, methods=['GET'])
@jwt_required()
def fetch_movies():
    username = get_jwt_identity()
    return make_response(jsonify(Movies.objects()), 200)

# User can search for movie based on the title
@movies_bp.route(Config.SEARCH_MOVIE, methods=['GET'])
@jwt_required()
def search_movie():
    username = get_jwt_identity()
    title = request.args.get('title')  # Fetch title from query parameters
    try:
        movie = Movies.objects.get(title=title)
        return make_response(jsonify(movie), 200)
    except Movies.DoesNotExist:
        abort(404)

# User can delete movie based on the title
@movies_bp.route(Config.DELETE_MOVIE, methods=['DELETE'])
@jwt_required()
def delete_movie():
    username = get_jwt_identity()
    title = request.args.get('title')  # Fetch title from query parameters
    movie = Movies.objects(title=title).first()
    if not movie:
        abort(404)
    movie.delete()
    return make_response(jsonify({"success": "Movie Deleted Successfully"}), 200)

# User can add/remove movies as per their favourites
@movies_bp.route(Config.ADD_TO_FAVOURITE, methods=['PUT'])
@jwt_required()
def add_to_favourite():
    username = get_jwt_identity()
    title = request.json.get('title')
    is_favourite = request.json.get('is_favourite')
    movie = Movies.objects(title=title).first()
    if not movie:
        abort(404)
    movie.update(is_favourite=is_favourite)
    message = f"{title} has been {'added to' if is_favourite else 'removed from'} your favourites"
    return make_response(jsonify({"success": message}), 200)

# Fetches list of favourite movies based on the username
@movies_bp.route(Config.FAVOURITE_MOVIES, methods=['GET'])
@jwt_required()
def favourite_movies():
    username = get_jwt_identity()
    favourites = Movies.objects(is_favourite=True)
    return make_response(jsonify(favourites), 200)

# User can add new movie into the database
@movies_bp.route(Config.ADD_MOVIE, methods=['POST'])
@jwt_required()
def add_movie():
    username = get_jwt_identity()
    try:
        movie_data = request.json
        new_movie = Movies(**movie_data)
        new_movie.save()
    except KeyError as e:
        abort(400)
    return make_response(jsonify({"success": "Movie Added Successfully"}), 201)

@movies_bp.errorhandler(400)
def invalid_request(error):
    return make_response(jsonify({'error': 'Invalid Request'}), 400)

@movies_bp.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Sorry, movie not found'}), 404)

@movies_bp.errorhandler(401)
def unauthorized(error):
    return make_response(jsonify({'error': 'Unauthorized Access'}), 401)
